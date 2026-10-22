import CryptoKit
import Darwin
import Dispatch
import Foundation
import LocalAuthentication
import Security

private let statusOk: Int32 = 0
private let statusCancelled: Int32 = 1
private let statusUnavailable: Int32 = 2
private let statusLockedOut: Int32 = 3
private let statusCorruptSidecar: Int32 = 4
private let statusFailed: Int32 = 5
private let interactionMayPrompt: Int32 = 0
private let interactionDisallowed: Int32 = 1
private let sidecarMagic = Data([0x56, 0x4c, 0x54, 0x53, 0x45])
private let sidecarVersion: UInt8 = 1
private let sidecarHeaderLength = 18
private let maximumInputLength = 1 << 20
private let publicKeyLength = 65
private let sealedBoxMinimumLength = 12 + 16
private let keyInfo = Data("vault-secure-enclave-identity-v1".utf8)
private let bindingInfo = Data("vault-secure-enclave-binding-v1".utf8)

private struct BridgeFailure: Error {
    let status: Int32
    let message: String
}

private struct Sidecar {
    let keyRepresentation: Data
    let ephemeralPublicKey: Data
    let sealed: Data
}

private func allocate(_ bytes: Data, pointer: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>, length: UnsafeMutablePointer<Int>) -> Bool {
    guard !bytes.isEmpty, let raw = malloc(bytes.count) else {
        pointer.pointee = nil
        length.pointee = 0
        return false
    }
    let output = raw.assumingMemoryBound(to: UInt8.self)
    bytes.copyBytes(to: output, count: bytes.count)
    pointer.pointee = output
    length.pointee = bytes.count
    return true
}

private func fail(_ error: BridgeFailure, pointer: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>, length: UnsafeMutablePointer<Int>) -> Int32 {
    let message = Data(error.message.utf8)
    _ = allocate(message, pointer: pointer, length: length)
    return error.status
}

private func readInput(_ pointer: UnsafePointer<UInt8>?, _ length: Int, maximum: Int = maximumInputLength) throws -> Data {
    guard length > 0, length <= maximum, let pointer else {
        throw BridgeFailure(status: statusFailed, message: "invalid or empty input buffer")
    }
    return Data(bytes: pointer, count: length)
}

@available(macOS 10.15, *)
private func accessControl() throws -> SecAccessControl {
    var error: Unmanaged<CFError>?
    guard let control = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .userPresence],
        &error
    ) else {
        if let error {
            throw BridgeFailure(status: statusFailed, message: String(describing: error.takeRetainedValue()))
        }
        throw BridgeFailure(status: statusFailed, message: "could not create Secure Enclave access control")
    }
    return control
}

@available(macOS 10.15, *)
private func classify(_ error: Error) -> BridgeFailure {
    let nsError = error as NSError
    if nsError.domain == LAError.errorDomain, let code = LAError.Code(rawValue: nsError.code) {
        switch code {
        case .userCancel, .appCancel, .systemCancel:
            return BridgeFailure(status: statusCancelled, message: "authentication was cancelled")
        case .biometryLockout:
            return BridgeFailure(status: statusLockedOut, message: nsError.localizedDescription)
        case .biometryNotAvailable, .biometryNotEnrolled, .passcodeNotSet, .notInteractive:
            return BridgeFailure(status: statusUnavailable, message: nsError.localizedDescription)
        default:
            break
        }
    }
    if nsError.domain == NSOSStatusErrorDomain {
        switch Int32(nsError.code) {
        case errSecUserCanceled:
            return BridgeFailure(status: statusCancelled, message: "authentication was cancelled")
        case errSecInteractionNotAllowed:
            return BridgeFailure(status: statusUnavailable, message: nsError.localizedDescription)
        default:
            break
        }
    }
    return BridgeFailure(status: statusFailed, message: nsError.localizedDescription)
}

@available(macOS 10.15, *)
private func authenticate(_ context: LAContext, interaction: Int32) throws {
    let policy: LAPolicy = .deviceOwnerAuthentication
    if interaction == interactionDisallowed {
        context.interactionNotAllowed = true
    } else if interaction != interactionMayPrompt {
        throw BridgeFailure(status: statusFailed, message: "unknown interaction policy")
    }
    var policyError: NSError?
    guard context.canEvaluatePolicy(policy, error: &policyError) else {
        throw classify(policyError ?? BridgeFailure(status: statusFailed, message: "authentication policy is unavailable"))
    }
    let completion = DispatchSemaphore(value: 0)
    var result: Result<Void, Error> = .success(())
    context.evaluatePolicy(policy, localizedReason: "Unlock vault identity") { success, error in
        if !success {
            result = .failure(error ?? BridgeFailure(status: statusFailed, message: "authentication failed without an error"))
        }
        completion.signal()
    }
    completion.wait()
    if case let .failure(error) = result {
        throw classify(error)
    }
}

private func associatedData(binding: Data, ephemeralPublicKey: Data) -> Data {
    var data = sidecarMagic
    data.append(sidecarVersion)
    data.append(bindingInfo)
    data.append(binding)
    data.append(ephemeralPublicKey)
    return data
}

@available(macOS 10.15, *)
private func deriveKey(
    _ sharedSecret: SharedSecret,
    _ ephemeralPublicKey: P256.KeyAgreement.PublicKey,
    _ recipientPublicKey: P256.KeyAgreement.PublicKey
) -> SymmetricKey {
    sharedSecret.hkdfDerivedSymmetricKey(
        using: SHA256.self,
        salt: ephemeralPublicKey.x963Representation + recipientPublicKey.x963Representation,
        sharedInfo: keyInfo,
        outputByteCount: 32
    )
}

private func appendLength(_ length: Int, to data: inout Data) {
    let value = UInt32(length)
    data.append(UInt8((value >> 24) & 0xff))
    data.append(UInt8((value >> 16) & 0xff))
    data.append(UInt8((value >> 8) & 0xff))
    data.append(UInt8(value & 0xff))
}

private func encode(_ sidecar: Sidecar) throws -> Data {
    guard sidecar.keyRepresentation.count <= maximumInputLength,
          sidecar.ephemeralPublicKey.count == publicKeyLength,
          sidecar.sealed.count >= sealedBoxMinimumLength,
          sidecar.sealed.count <= maximumInputLength else {
        throw BridgeFailure(status: statusFailed, message: "invalid Secure Enclave sidecar fields")
    }
    var data = sidecarMagic
    data.append(sidecarVersion)
    appendLength(sidecar.keyRepresentation.count, to: &data)
    appendLength(sidecar.ephemeralPublicKey.count, to: &data)
    appendLength(sidecar.sealed.count, to: &data)
    data.append(sidecar.keyRepresentation)
    data.append(sidecar.ephemeralPublicKey)
    data.append(sidecar.sealed)
    return data
}

private func readLength(_ bytes: [UInt8], at offset: Int) -> Int {
    (Int(bytes[offset]) << 24) | (Int(bytes[offset + 1]) << 16) | (Int(bytes[offset + 2]) << 8) | Int(bytes[offset + 3])
}

private func decodeSidecar(_ data: Data) throws -> Sidecar {
    guard data.count >= sidecarHeaderLength,
          data.count <= maximumInputLength,
          data.prefix(sidecarMagic.count) == sidecarMagic,
          data[sidecarMagic.count] == sidecarVersion else {
        throw BridgeFailure(status: statusCorruptSidecar, message: "unsupported or truncated Secure Enclave sidecar")
    }
    let bytes = [UInt8](data)
    let keyLength = readLength(bytes, at: 6)
    let ephemeralLength = readLength(bytes, at: 10)
    let sealedLength = readLength(bytes, at: 14)
    guard keyLength > 0,
          keyLength <= maximumInputLength,
          ephemeralLength == publicKeyLength,
          sealedLength >= sealedBoxMinimumLength,
          sealedLength <= maximumInputLength,
          keyLength <= bytes.count - sidecarHeaderLength,
          ephemeralLength <= bytes.count - sidecarHeaderLength - keyLength,
          sealedLength == bytes.count - sidecarHeaderLength - keyLength - ephemeralLength else {
        throw BridgeFailure(status: statusCorruptSidecar, message: "invalid Secure Enclave sidecar lengths")
    }
    let keyStart = sidecarHeaderLength
    let ephemeralStart = keyStart + keyLength
    let sealedStart = ephemeralStart + ephemeralLength
    return Sidecar(
        keyRepresentation: Data(bytes[keyStart..<ephemeralStart]),
        ephemeralPublicKey: Data(bytes[ephemeralStart..<sealedStart]),
        sealed: Data(bytes[sealedStart..<bytes.count])
    )
}

@available(macOS 10.15, *)
private func wrapIdentity(_ identityPointer: UnsafePointer<UInt8>?, _ identityLength: Int, _ bindingPointer: UnsafePointer<UInt8>?, _ bindingLength: Int) throws -> Data {
    guard SecureEnclave.isAvailable else {
        throw BridgeFailure(status: statusUnavailable, message: "Secure Enclave is unavailable")
    }
    var identity = try readInput(identityPointer, identityLength)
    defer { identity.resetBytes(in: identity.startIndex..<identity.endIndex) }
    let binding = try readInput(bindingPointer, bindingLength)
    let recipient = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: accessControl())
    let ephemeral = P256.KeyAgreement.PrivateKey()
    let sharedSecret = try ephemeral.sharedSecretFromKeyAgreement(with: recipient.publicKey)
    let sharedKey = deriveKey(sharedSecret, ephemeral.publicKey, recipient.publicKey)
    let ephemeralRepresentation = ephemeral.publicKey.x963Representation
    let aad = associatedData(binding: binding, ephemeralPublicKey: ephemeralRepresentation)
    let sealed = try ChaChaPoly.seal(identity, using: sharedKey, authenticating: aad)
    return try encode(Sidecar(
        keyRepresentation: recipient.dataRepresentation,
        ephemeralPublicKey: ephemeralRepresentation,
        sealed: sealed.combined
    ))
}

@available(macOS 10.15, *)
private func unwrapIdentity(
    _ sidecarPointer: UnsafePointer<UInt8>?,
    _ sidecarLength: Int,
    _ bindingPointer: UnsafePointer<UInt8>?,
    _ bindingLength: Int,
    _ interaction: Int32,
    _ outputPointer: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ outputLength: UnsafeMutablePointer<Int>
) throws {
    guard SecureEnclave.isAvailable else {
        throw BridgeFailure(status: statusUnavailable, message: "Secure Enclave is unavailable")
    }
    let sidecarData = try readInput(sidecarPointer, sidecarLength)
    let binding = try readInput(bindingPointer, bindingLength)
    let sidecar = try decodeSidecar(sidecarData)
    let context = LAContext()
    defer { context.invalidate() }
    if interaction == interactionDisallowed {
        context.interactionNotAllowed = true
    } else if interaction != interactionMayPrompt {
        throw BridgeFailure(status: statusFailed, message: "unknown interaction policy")
    }
    let recipient: SecureEnclave.P256.KeyAgreement.PrivateKey
    let ephemeralPublicKey: P256.KeyAgreement.PublicKey
    let sealed: ChaChaPoly.SealedBox
    do {
        recipient = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: sidecar.keyRepresentation,
            authenticationContext: context
        )
        ephemeralPublicKey = try P256.KeyAgreement.PublicKey(x963Representation: sidecar.ephemeralPublicKey)
        sealed = try ChaChaPoly.SealedBox(combined: sidecar.sealed)
    } catch {
        let classified = classify(error)
        if classified.status == statusFailed {
            throw BridgeFailure(status: statusCorruptSidecar, message: classified.message)
        }
        throw classified
    }
    try authenticate(context, interaction: interaction)
    let sharedSecret: SharedSecret
    do {
        sharedSecret = try recipient.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
    } catch {
        throw classify(error)
    }
    let sharedKey = deriveKey(sharedSecret, ephemeralPublicKey, recipient.publicKey)
    let aad = associatedData(binding: binding, ephemeralPublicKey: sidecar.ephemeralPublicKey)
    var identity: Data
    do {
        identity = try ChaChaPoly.open(sealed, using: sharedKey, authenticating: aad)
    } catch {
        throw BridgeFailure(status: statusCorruptSidecar, message: "identity envelope authentication failed")
    }
    defer { identity.resetBytes(in: identity.startIndex..<identity.endIndex) }
    guard allocate(identity, pointer: outputPointer, length: outputLength) else {
        throw BridgeFailure(status: statusFailed, message: "could not allocate unwrapped identity output")
    }
}

@_cdecl("vault_se_wrap_identity")
public func vaultSeWrapIdentity(
    _ identityPointer: UnsafePointer<UInt8>?,
    _ identityLength: Int,
    _ bindingPointer: UnsafePointer<UInt8>?,
    _ bindingLength: Int,
    _ outputPointer: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ outputLength: UnsafeMutablePointer<Int>,
    _ errorPointer: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ errorLength: UnsafeMutablePointer<Int>
) -> Int32 {
    outputPointer.pointee = nil
    outputLength.pointee = 0
    errorPointer.pointee = nil
    errorLength.pointee = 0
    guard #available(macOS 10.15, *) else {
        return fail(BridgeFailure(status: statusUnavailable, message: "Secure Enclave CryptoKit APIs require macOS 10.15"), pointer: errorPointer, length: errorLength)
    }
    do {
        let sidecar = try wrapIdentity(identityPointer, identityLength, bindingPointer, bindingLength)
        guard allocate(sidecar, pointer: outputPointer, length: outputLength) else {
            throw BridgeFailure(status: statusFailed, message: "could not allocate Secure Enclave sidecar output")
        }
        return statusOk
    } catch let error as BridgeFailure {
        return fail(error, pointer: errorPointer, length: errorLength)
    } catch {
        let classified = classify(error)
        return fail(classified, pointer: errorPointer, length: errorLength)
    }
}

@_cdecl("vault_se_validate_sidecar")
public func vaultSeValidateSidecar(
    _ sidecarPointer: UnsafePointer<UInt8>?,
    _ sidecarLength: Int,
    _ errorPointer: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ errorLength: UnsafeMutablePointer<Int>
) -> Int32 {
    errorPointer.pointee = nil
    errorLength.pointee = 0
    do {
        let sidecarData: Data
        do {
            sidecarData = try readInput(sidecarPointer, sidecarLength)
        } catch {
            throw BridgeFailure(status: statusCorruptSidecar, message: "sidecar length is invalid")
        }
        _ = try decodeSidecar(sidecarData)
        return statusOk
    } catch let error as BridgeFailure {
        return fail(error, pointer: errorPointer, length: errorLength)
    } catch {
        return fail(BridgeFailure(status: statusCorruptSidecar, message: "sidecar framing is invalid"), pointer: errorPointer, length: errorLength)
    }
}

@_cdecl("vault_se_unwrap_identity")
public func vaultSeUnwrapIdentity(
    _ sidecarPointer: UnsafePointer<UInt8>?,
    _ sidecarLength: Int,
    _ bindingPointer: UnsafePointer<UInt8>?,
    _ bindingLength: Int,
    _ interaction: Int32,
    _ outputPointer: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ outputLength: UnsafeMutablePointer<Int>,
    _ errorPointer: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ errorLength: UnsafeMutablePointer<Int>
) -> Int32 {
    outputPointer.pointee = nil
    outputLength.pointee = 0
    errorPointer.pointee = nil
    errorLength.pointee = 0
    guard #available(macOS 10.15, *) else {
        return fail(BridgeFailure(status: statusUnavailable, message: "Secure Enclave CryptoKit APIs require macOS 10.15"), pointer: errorPointer, length: errorLength)
    }
    do {
        try unwrapIdentity(sidecarPointer, sidecarLength, bindingPointer, bindingLength, interaction, outputPointer, outputLength)
        return statusOk
    } catch let error as BridgeFailure {
        return fail(error, pointer: errorPointer, length: errorLength)
    } catch {
        return fail(classify(error), pointer: errorPointer, length: errorLength)
    }
}

@_cdecl("vault_se_free")
public func vaultSeFree(_ pointer: UnsafeMutablePointer<UInt8>?, _ length: Int) {
    guard let pointer else { return }
    if length > 0 {
        memset(pointer, 0, length)
    }
    free(pointer)
}
