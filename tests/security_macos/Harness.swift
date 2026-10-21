import Foundation
import LocalAuthentication
import Security

enum Backend {
    case file
    case dataProtection
}

let service = "dev.joshuarli.vault.security-harness"
let suffixes = [
    "file-default",
    "file-user-presence",
    "file-lock",
    "dp-probe",
    "dp-protected-one",
    "dp-protected-two",
    "dp-update-data",
    "dp-update-acl",
    "dp-interactive-one",
    "dp-interactive-two"
]

func validRunID(_ value: String) -> Bool {
    value.count == 32 && value.allSatisfy { "0123456789abcdef".contains($0) }
}

func account(_ runID: String, _ suffix: String) -> String {
    "vault-harness.\(runID).\(suffix)"
}

func secret(_ runID: String, _ suffix: String, version: UInt8 = 0) -> Data {
    let seed = Array((runID + suffix).utf8)
    return Data((0..<96).map { index in
        let byte = seed[index % seed.count]
        return UInt8(truncatingIfNeeded: Int(byte) &+ index &* 37 &+ Int(version))
    })
}

func statusName(_ status: OSStatus) -> String {
    switch status {
    case errSecSuccess: return "success"
    case errSecDuplicateItem: return "duplicate-item"
    case errSecItemNotFound: return "item-not-found"
    case errSecInteractionNotAllowed: return "interaction-not-allowed"
    case errSecAuthFailed: return "auth-failed"
    case errSecMissingEntitlement: return "missing-entitlement"
    case errSecParam: return "invalid-parameter"
    case errSecUserCanceled: return "user-cancelled"
    case errSecNotAvailable: return "not-available"
    default: return "osstatus-\(status)"
    }
}

func keychain(_ path: String) throws -> SecKeychain {
    var result: SecKeychain?
    let status = SecKeychainOpen(path, &result)
    guard status == errSecSuccess, let result else {
        throw HarnessError.keychain(status)
    }
    return result
}

enum HarnessError: Error {
    case keychain(OSStatus)
    case accessControl(String)
    case check(String)
    case item(OSStatus)
    case arguments
}

func printStatus(_ label: String, _ status: OSStatus) {
    print("\(label)=\(statusName(status))")
}

func accessControl(userPresence: Bool) throws -> SecAccessControl {
    var error: Unmanaged<CFError>?
    let flags: SecAccessControlCreateFlags = userPresence ? [.userPresence] : []
    guard let control = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        flags,
        &error
    ) else {
        throw HarnessError.accessControl(error?.takeRetainedValue().localizedDescription ?? "creation-failed")
    }
    return control
}

func baseQuery(_ runID: String, _ suffix: String, _ backend: Backend) -> [String: Any] {
    var query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account(runID, suffix),
        kSecAttrSynchronizable as String: false,
        kSecUseDataProtectionKeychain as String: backend == .dataProtection
    ]
    if backend == .dataProtection,
       let group = Bundle.main.infoDictionary?["VaultHarnessAccessGroup"] as? String {
        query[kSecAttrAccessGroup as String] = group
    }
    return query
}

func add(_ runID: String, _ suffix: String, _ backend: Backend, _ fileKeychain: SecKeychain?, protected: Bool) throws -> OSStatus {
    var query = baseQuery(runID, suffix, backend)
    if backend == .file, let fileKeychain {
        query[kSecUseKeychain as String] = fileKeychain
    }
    query[kSecValueData as String] = secret(runID, suffix)
    if protected {
        query[kSecAttrAccessControl as String] = try accessControl(userPresence: true)
    }
    return SecItemAdd(query as CFDictionary, nil)
}

func read(_ runID: String, _ suffix: String, _ backend: Backend, _ fileKeychain: SecKeychain?, context: LAContext? = nil, expectedVersion: UInt8 = 0, accessGroup: String? = nil) -> (OSStatus, Bool) {
    var query = baseQuery(runID, suffix, backend)
    if backend == .dataProtection, let accessGroup {
        query[kSecAttrAccessGroup as String] = accessGroup
    }
    if backend == .file, let fileKeychain {
        query[kSecMatchSearchList as String] = [fileKeychain]
    }
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    if let context {
        query[kSecUseAuthenticationContext as String] = context
    }
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    let matches = (result as? Data) == secret(runID, suffix, version: expectedVersion)
    return (status, matches)
}

func expect(_ condition: Bool, _ description: String) throws {
    guard condition else { throw HarnessError.check(description) }
}

func printSession() throws {
    let current = ProcessInfo.processInfo
    let onTTY = isatty(STDIN_FILENO) == 1
    let underSSH = current.environment["SSH_TTY"] != nil || current.environment["SSH_CONNECTION"] != nil
    let tmuxPath = (try? shellOutput("/usr/bin/which", ["tmux"])) ?? ""
    let tmuxPresent = current.environment["TMUX"] != nil
    let tmuxAttached = tmuxPresent && !tmuxPath.isEmpty ? ((try? shellOutput(tmuxPath, ["display-message", "-p", "#{session_attached}"])) ?? "unavailable") : "unavailable"
    let consoleUID = try shellOutput("/usr/bin/stat", ["-f", "%u", "/dev/console"])
    let managerUID = (try? shellOutput("/bin/launchctl", ["manageruid"])) ?? "unavailable"
    print("session=stdin_tty:\(onTTY ? "yes" : "no") ssh:\(underSSH ? "yes" : "no") tmux:\(tmuxPresent ? "yes" : "no") tmux_attached:\(tmuxAttached) console_user_matches:\(consoleUID == String(getuid()) ? "yes" : "no") launchd_manager_uid:\(managerUID)")
}

func printAuthenticationCapabilities() {
    let context = LAContext()
    defer { context.invalidate() }
    var biometryError: NSError?
    let biometryAvailable = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &biometryError)
    var ownerAuthenticationError: NSError?
    let ownerAuthenticationAvailable = context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &ownerAuthenticationError)
    let biometry: String
    switch context.biometryType {
    case .touchID: biometry = "touch-id"
    case .faceID: biometry = "face-id"
    case .opticID: biometry = "optic-id"
    case .none: biometry = "none"
    @unknown default: biometry = "unknown"
    }
    print("authentication_capability=biometry:\(biometry) biometry_available:\(biometryAvailable ? "yes" : "no") biometry_error_code:\(biometryError?.code ?? 0) device_owner_authentication_available:\(ownerAuthenticationAvailable ? "yes" : "no") owner_authentication_error_code:\(ownerAuthenticationError?.code ?? 0)")
}

func runSuite(_ runID: String, _ keychainPath: String) throws {
    try printSession()
    if let group = Bundle.main.infoDictionary?["VaultHarnessAccessGroup"] as? String {
        print("data_protection_access_group=\(group)")
    }
    let fileKeychain = try keychain(keychainPath)
    let fileAdd = try add(runID, "file-default", .file, fileKeychain, protected: false)
    printStatus("file_add_without_data_protection", fileAdd)
    try expect(fileAdd == errSecSuccess, "file-based add failed")

    let lockAdd = try add(runID, "file-lock", .file, fileKeychain, protected: false)
    printStatus("file_lock_probe_add", lockAdd)
    try expect(lockAdd == errSecSuccess, "file lock probe add failed")

    let fileProtectedAdd = try add(runID, "file-user-presence", .file, fileKeychain, protected: true)
    printStatus("file_user_presence_add", fileProtectedAdd)
    try expect(fileProtectedAdd == errSecSuccess, "file userPresence add failed")
    let fileContext = LAContext()
    fileContext.interactionNotAllowed = true
    let (fileProtectedRead, fileProtectedMatches) = read(runID, "file-user-presence", .file, fileKeychain, context: fileContext)
    print("file_user_presence_noninteractive_read=\(statusName(fileProtectedRead)) data_matches=\(fileProtectedMatches)")
    try expect(fileProtectedRead == errSecSuccess && fileProtectedMatches, "file userPresence item was not readable without interaction")

    let (fileRead, fileMatches) = read(runID, "file-default", .file, fileKeychain)
    print("file_query_status=\(statusName(fileRead)) data_matches=\(fileMatches)")
    try expect(fileRead == errSecSuccess && fileMatches, "file-based exact query failed")

    let (wrongDomainRead, _) = read(runID, "file-default", .dataProtection, nil)
    printStatus("data_protection_query_for_file_item", wrongDomainRead)
    try expect(wrongDomainRead == errSecItemNotFound, "file item appeared in data protection query")

    let dpAdd = try add(runID, "dp-probe", .dataProtection, nil, protected: false)
    printStatus("data_protection_add", dpAdd)
    guard dpAdd == errSecSuccess else {
        if dpAdd == errSecMissingEntitlement || dpAdd == errSecNotAvailable {
            print("data_protection=blocked status=\(statusName(dpAdd))")
            return
        }
        throw HarnessError.item(dpAdd)
    }

    let (dpRead, dpMatches) = read(runID, "dp-probe", .dataProtection, nil)
    print("data_protection_query_status=\(statusName(dpRead)) data_matches=\(dpMatches)")
    try expect(dpRead == errSecSuccess && dpMatches, "data protection exact query failed")

    let (wrongFileRead, _) = read(runID, "dp-probe", .file, fileKeychain)
    printStatus("file_query_for_data_protection_item", wrongFileRead)
    try expect(wrongFileRead == errSecItemNotFound, "data protection item appeared in file query")

    for protectedSuffix in ["dp-protected-one", "dp-protected-two", "dp-update-data", "dp-update-acl"] {
        let protectedAdd = try add(runID, protectedSuffix, .dataProtection, nil, protected: true)
        printStatus("user_presence_add_\(protectedSuffix)", protectedAdd)
        try expect(protectedAdd == errSecSuccess, "userPresence item add failed")
    }

    let deniedContext = LAContext()
    deniedContext.interactionNotAllowed = true
    let (deniedRead, _) = read(runID, "dp-protected-one", .dataProtection, nil, context: deniedContext)
    printStatus("noninteractive_user_presence_read", deniedRead)
    try expect(deniedRead == errSecInteractionNotAllowed || deniedRead == errSecAuthFailed, "noninteractive protected read did not deny access")

    let updateContext = LAContext()
    updateContext.interactionNotAllowed = true
    var updateQuery = baseQuery(runID, "dp-update-data", .dataProtection)
    updateQuery[kSecUseAuthenticationContext as String] = updateContext
    let updateStatus = SecItemUpdate(
        updateQuery as CFDictionary,
        [kSecValueData as String: secret(runID, "dp-update-data", version: 1)] as CFDictionary
    )
    printStatus("data_only_update", updateStatus)
    try expect(updateStatus == errSecSuccess || updateStatus == errSecInteractionNotAllowed || updateStatus == errSecAuthFailed, "data-only update returned an unexpected status")
    let (afterDataUpdate, _) = read(runID, "dp-update-data", .dataProtection, nil, context: updateContext, expectedVersion: 1)
    printStatus("noninteractive_read_after_data_only_update", afterDataUpdate)
    if updateStatus == errSecSuccess {
        try expect(afterDataUpdate == errSecInteractionNotAllowed || afterDataUpdate == errSecAuthFailed, "data-only update removed userPresence enforcement")
    } else {
        let (beforeVersion, beforeVersionMatches) = read(runID, "dp-update-data", .dataProtection, nil, context: updateContext)
        print("noninteractive_read_after_blocked_data_update=\(statusName(beforeVersion)) data_matches=\(beforeVersionMatches)")
        try expect(beforeVersion == errSecInteractionNotAllowed || beforeVersion == errSecAuthFailed, "blocked data update left a readable protected item")
    }

    let weakerControl = try accessControl(userPresence: false)
    let aclContext = LAContext()
    aclContext.interactionNotAllowed = true
    var aclQuery = baseQuery(runID, "dp-update-acl", .dataProtection)
    aclQuery[kSecUseAuthenticationContext as String] = aclContext
    let aclStatus = SecItemUpdate(
        aclQuery as CFDictionary,
        [kSecAttrAccessControl as String: weakerControl] as CFDictionary
    )
    printStatus("access_control_update_to_unprotected", aclStatus)
    let (afterACLUpdate, aclMatches) = read(runID, "dp-update-acl", .dataProtection, nil, context: aclContext)
    print("noninteractive_read_after_access_control_update=\(statusName(afterACLUpdate)) data_matches=\(aclMatches)")
    try expect(aclStatus == errSecSuccess || aclStatus == errSecInteractionNotAllowed || aclStatus == errSecAuthFailed, "access-control update returned an unexpected status")
    if aclStatus == errSecSuccess {
        try expect(afterACLUpdate == errSecInteractionNotAllowed || afterACLUpdate == errSecAuthFailed, "successful access-control update removed userPresence enforcement")
    } else {
        try expect(afterACLUpdate == errSecInteractionNotAllowed || afterACLUpdate == errSecAuthFailed, "blocked access-control update left a readable protected item")
    }
}

func runInteractive(_ runID: String, _ keychainPath: String) throws {
    try printSession()
    printAuthenticationCapabilities()
    print("hardware_model=\(try shellOutput("/usr/sbin/sysctl", ["-n", "hw.model"]))")
    print("macos_version=\(try shellOutput("/usr/bin/sw_vers", ["-productVersion"]))")
    print("architecture=\(try shellOutput("/usr/bin/uname", ["-m"]))")
    print("signing_identity=ad-hoc")

    let one = try add(runID, "dp-interactive-one", .dataProtection, nil, protected: true)
    let two = try add(runID, "dp-interactive-two", .dataProtection, nil, protected: true)
    printStatus("interactive_item_one_add", one)
    printStatus("interactive_item_two_add", two)
    if one == errSecMissingEntitlement || one == errSecNotAvailable {
        print("interactive=blocked status=\(statusName(one))")
        return
    }
    try expect(one == errSecSuccess && two == errSecSuccess, "interactive userPresence item add failed")

    let context = LAContext()
    context.localizedReason = "Review isolated Keychain harness authorization"
    context.touchIDAuthenticationAllowableReuseDuration = 0
    defer { context.invalidate() }
    let (first, firstMatches) = read(runID, "dp-interactive-one", .dataProtection, nil, context: context)
    print("same_context_read_one=\(statusName(first)) data_matches=\(firstMatches)")
    try expect(first == errSecSuccess && firstMatches, "interactive first protected read failed")
    context.interactionNotAllowed = true
    let (second, secondMatches) = read(runID, "dp-interactive-two", .dataProtection, nil, context: context)
    print("same_context_read_two=\(statusName(second)) data_matches=\(secondMatches)")
    try expect(second == errSecSuccess && secondMatches, "interactive second protected read failed")

    let child = Process()
    child.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
    child.arguments = ["separate-invocation-read", runID]
    child.standardInput = FileHandle.standardInput
    child.standardOutput = FileHandle.standardOutput
    child.standardError = FileHandle.standardError
    try child.run()
    child.waitUntilExit()
    print("separate_invocation_exit=\(child.terminationStatus)")
    try expect(child.terminationStatus == 0, "separate protected invocation failed")
    try cleanup(runID, keychainPath, context: context)
}

func runSeparateInvocationRead(_ runID: String) throws {
    let context = LAContext()
    context.interactionNotAllowed = true
    defer { context.invalidate() }
    let (status, matches) = read(runID, "dp-interactive-one", .dataProtection, nil, context: context)
    print("fresh_context_separate_invocation=\(statusName(status)) data_matches=\(matches)")
    try expect(status == errSecInteractionNotAllowed || status == errSecAuthFailed, "separate invocation accessed item without fresh authorization")
}

func validAccessGroup(_ value: String) -> Bool {
    !value.isEmpty && value.count <= 255 && value.allSatisfy { "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-".contains($0) }
}

func runCrossIdentityRead(_ runID: String, accessGroup: String?) throws {
    let context = LAContext()
    context.interactionNotAllowed = true
    defer { context.invalidate() }
    let (omittedGroupStatus, omittedGroupMatches) = read(runID, "dp-probe", .dataProtection, nil, context: context)
    print("ad_hoc_read_without_access_group=\(statusName(omittedGroupStatus)) data_matches=\(omittedGroupMatches)")
    if omittedGroupStatus == errSecSuccess && omittedGroupMatches {
        throw HarnessError.check("ad-hoc executable read the signed item without an access group")
    }
    if omittedGroupStatus == errSecItemNotFound {
        print("ad_hoc_read_without_access_group_result=item-not-found-with-group-omitted")
    }
    try expect(omittedGroupStatus == errSecSuccess || omittedGroupStatus == errSecItemNotFound || omittedGroupStatus == errSecMissingEntitlement || omittedGroupStatus == errSecInteractionNotAllowed || omittedGroupStatus == errSecAuthFailed, "cross-identity query without a group failed unexpectedly")
    guard let accessGroup else { return }
    let (sameGroupStatus, sameGroupMatches) = read(runID, "dp-probe", .dataProtection, nil, context: context, accessGroup: accessGroup)
    print("ad_hoc_read_same_access_group=\(statusName(sameGroupStatus)) data_matches=\(sameGroupMatches)")
    if sameGroupStatus == errSecSuccess && sameGroupMatches {
        throw HarnessError.check("ad-hoc executable read the signed item through its exact access group")
    }
    try expect(sameGroupStatus == errSecItemNotFound || sameGroupStatus == errSecMissingEntitlement || sameGroupStatus == errSecInteractionNotAllowed || sameGroupStatus == errSecAuthFailed, "same-group cross-identity read failed unexpectedly")
}

func verifyFileLock(_ runID: String, _ keychainPath: String) throws {
    let fileKeychain = try keychain(keychainPath)
    let (status, matches) = read(runID, "file-lock", .file, fileKeychain)
    print("file_read_after_partition_list_command=\(statusName(status)) data_matches=\(matches)")
    try expect(status == errSecSuccess && matches, "file read after partition-list command failed")
}

func verifyFileUserPresence(_ runID: String, _ keychainPath: String, _ stage: String) throws {
    let fileKeychain = try keychain(keychainPath)
    let context = LAContext()
    context.interactionNotAllowed = true
    defer { context.invalidate() }
    let (status, matches) = read(runID, "file-user-presence", .file, fileKeychain, context: context)
    print("file_user_presence_\(stage)=\(statusName(status)) data_matches=\(matches)")
    try expect(status == errSecSuccess && matches, "file userPresence item changed across partition-list operation")
}

func cleanup(_ runID: String, _ keychainPath: String?, context: LAContext? = nil) throws {
    var firstFailure: OSStatus?
    var dataProtectionUnavailable = false
    let cleanupContext = context ?? LAContext()
    cleanupContext.interactionNotAllowed = true
    defer {
        if context == nil {
            cleanupContext.invalidate()
        }
    }
    for suffix in suffixes {
        var query = baseQuery(runID, suffix, .dataProtection)
        query[kSecUseAuthenticationContext as String] = cleanupContext
        let status = SecItemDelete(query as CFDictionary)
        if status == errSecMissingEntitlement {
            dataProtectionUnavailable = true
        } else if status != errSecSuccess && status != errSecItemNotFound {
            printStatus("cleanup_data_protection_\(suffix)", status)
            firstFailure = firstFailure ?? status
        } else {
            let verifyStatus = SecItemDelete(query as CFDictionary)
            if verifyStatus != errSecItemNotFound {
                printStatus("cleanup_verify_data_protection_\(suffix)", verifyStatus)
                firstFailure = firstFailure ?? verifyStatus
            }
        }
        query = baseQuery(runID, suffix, .file)
        if let keychainPath, FileManager.default.fileExists(atPath: keychainPath), let fileKeychain = try? keychain(keychainPath) {
            query[kSecMatchSearchList as String] = [fileKeychain]
            let fileStatus = SecItemDelete(query as CFDictionary)
            if fileStatus != errSecSuccess && fileStatus != errSecItemNotFound {
                printStatus("cleanup_file_\(suffix)", fileStatus)
                firstFailure = firstFailure ?? fileStatus
            } else {
                let verifyStatus = SecItemDelete(query as CFDictionary)
                if verifyStatus != errSecItemNotFound {
                    printStatus("cleanup_verify_file_\(suffix)", verifyStatus)
                    firstFailure = firstFailure ?? verifyStatus
                }
            }
        }
    }
    if dataProtectionUnavailable {
        print("cleanup_data_protection=unavailable_missing_entitlement")
    }
    if let firstFailure { throw HarnessError.item(firstFailure) }
}

func shellOutput(_ path: String, _ arguments: [String]) throws -> String {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: path)
    process.arguments = arguments
    let output = Pipe()
    process.standardOutput = output
    process.standardError = FileHandle.standardError
    try process.run()
    process.waitUntilExit()
    let data = output.fileHandleForReading.readDataToEndOfFile()
    guard process.terminationStatus == 0, let result = String(data: data, encoding: .utf8) else {
        throw HarnessError.check("host metadata command failed")
    }
    return result.trimmingCharacters(in: .whitespacesAndNewlines)
}

do {
    let arguments = Array(CommandLine.arguments.dropFirst())
    guard let mode = arguments.first else { throw HarnessError.arguments }
    switch mode {
    case "suite":
        guard arguments.count == 3, validRunID(arguments[1]) else { throw HarnessError.arguments }
        try runSuite(arguments[1], arguments[2])
    case "interactive":
        guard arguments.count == 3, validRunID(arguments[1]) else { throw HarnessError.arguments }
        try runInteractive(arguments[1], arguments[2])
    case "separate-invocation-read":
        guard arguments.count == 2, validRunID(arguments[1]) else { throw HarnessError.arguments }
        try runSeparateInvocationRead(arguments[1])
    case "cross-identity-read":
        guard (arguments.count == 2 || arguments.count == 3), validRunID(arguments[1]) else { throw HarnessError.arguments }
        let accessGroup = arguments.count == 3 ? arguments[2] : nil
        guard accessGroup.map(validAccessGroup) ?? true else { throw HarnessError.arguments }
        try runCrossIdentityRead(arguments[1], accessGroup: accessGroup)
    case "verify-file-lock":
        guard arguments.count == 3, validRunID(arguments[1]) else { throw HarnessError.arguments }
        try verifyFileLock(arguments[1], arguments[2])
    case "verify-file-user-presence":
        guard arguments.count == 4, validRunID(arguments[1]), ["before-lock", "after-lock"].contains(arguments[3]) else { throw HarnessError.arguments }
        try verifyFileUserPresence(arguments[1], arguments[2], arguments[3])
    case "cleanup":
        guard arguments.count == 3, validRunID(arguments[1]) else { throw HarnessError.arguments }
        try cleanup(arguments[1], arguments[2])
    default:
        throw HarnessError.arguments
    }
} catch HarnessError.arguments {
    fputs("invalid harness invocation\n", stderr)
    exit(2)
} catch HarnessError.keychain(let status) {
    fputs("file_keychain_open=\(statusName(status))\n", stderr)
    exit(1)
} catch HarnessError.item(let status) {
    fputs("keychain_operation=\(statusName(status))\n", stderr)
    exit(1)
} catch HarnessError.accessControl(let reason) {
    fputs("access_control_creation=\(reason)\n", stderr)
    exit(1)
} catch HarnessError.check(let reason) {
    fputs("harness_check=\(reason)\n", stderr)
    exit(1)
} catch {
    fputs("harness_error=\(error.localizedDescription)\n", stderr)
    exit(1)
}
