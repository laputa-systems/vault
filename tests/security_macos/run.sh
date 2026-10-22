#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
SCRATCH="$ROOT/.work/tmp"
TMPDIR="$SCRATCH"
export TMPDIR

git -C "$ROOT" check-ignore -q .work/tmp || {
    printf '%s\n' '.work/tmp must be ignored through .git/info/exclude' >&2
    exit 1
}
mkdir -p "$SCRATCH"

MODE=${1:-default}
if [ "$#" -gt 1 ]; then
    printf '%s\n' 'usage: tests/security_macos/run.sh [--gate|--interactive]' >&2
    exit 2
fi
case "$MODE" in
    default|--gate|--interactive) ;;
    *)
        printf '%s\n' 'usage: tests/security_macos/run.sh [--gate|--interactive]' >&2
        exit 2
        ;;
esac

if [ "$MODE" = --interactive ] && [ ! -t 0 ]; then
    printf '%s\n' 'interactive mode requires a terminal; no Keychain reads were attempted' >&2
    exit 2
fi

RUN_ID=$(uuidgen | tr '[:upper:]' '[:lower:]' | tr -d '-')
case "$RUN_ID" in
    *[!0-9a-f]*|'')
        printf '%s\n' 'uuidgen returned an invalid run identifier' >&2
        exit 1
        ;;
esac
if [ "${#RUN_ID}" -ne 32 ]; then
    printf '%s\n' 'uuidgen returned an invalid run identifier' >&2
    exit 1
fi

KEYCHAIN="$SCRATCH/security-harness-$RUN_ID.keychain-db"
KEYCHAIN_PASSWORD="$(uuidgen)$(uuidgen)"
BIN="$SCRATCH/security-harness-$RUN_ID"
IDENTITY_BIN="$SCRATCH/security-harness-$RUN_ID-identity"
APP="$SCRATCH/security-harness-$RUN_ID.app"
APP_BIN="$APP/Contents/MacOS/vault-security-harness"
PROFILE_SCRATCH="$SCRATCH/security-harness-$RUN_ID-profiles"
INTERACTIVE_BIN=$BIN
INTERACTIVE_RUN_ID=$RUN_ID
RUN_IDS=$RUN_ID
IDENTITY_RUN_IDS=
PACKAGE_RUN_IDS=
ORIGINAL_SEARCH_LIST=$(security list-keychains -d user)

cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    if [ -x "$BIN" ]; then
        for run_id in $RUN_IDS; do
            "$BIN" cleanup "$run_id" "$KEYCHAIN" || result=1
        done
    fi
    if [ -x "$IDENTITY_BIN" ]; then
        for run_id in $IDENTITY_RUN_IDS; do
            "$IDENTITY_BIN" cleanup "$run_id" "$KEYCHAIN" || result=1
        done
    fi
    if [ -x "$APP_BIN" ]; then
        for run_id in $PACKAGE_RUN_IDS; do
            "$APP_BIN" cleanup "$run_id" "$KEYCHAIN" || result=1
        done
    fi
    if [ -e "$KEYCHAIN" ]; then
        security delete-keychain "$KEYCHAIN" >/dev/null 2>&1 || result=1
    fi
    if [ -e "$KEYCHAIN" ]; then
        printf '%s\n' 'cleanup=file-keychain-removal-failed' >&2
        result=1
    fi
    CURRENT_SEARCH_LIST=$(security list-keychains -d user)
    if [ "$CURRENT_SEARCH_LIST" != "$ORIGINAL_SEARCH_LIST" ]; then
        printf '%s\n' 'cleanup=keychain-search-list-not-restored' >&2
        result=1
    fi
    rm -f "$BIN" "$IDENTITY_BIN"
    rm -rf "$APP" "$PROFILE_SCRATCH"
    rm -rf "$SCRATCH/swift-module-cache-$RUN_ID"
    if [ "$result" -eq 0 ]; then
        printf '%s\n' 'cleanup=exact-records-deleted file-keychain-removed search-list-restored'
    else
        printf 'cleanup=failed status=%s\n' "$result" >&2
    fi
    exit "$result"
}
trap cleanup EXIT HUP INT TERM

swiftc -module-cache-path "$SCRATCH/swift-module-cache-$RUN_ID" \
    -o "$BIN" "$SCRIPT_DIR/Harness.swift"
codesign --force --sign - --timestamp=none "$BIN"
security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"

printf 'attempt=standalone-ad-hoc\n'
codesign --display --verbose=2 "$BIN" 2>&1 | sed -n '1,8p'
"$BIN" suite "$RUN_ID" "$KEYCHAIN"

FILE_LOCK_ACCOUNT="vault-harness.$RUN_ID.file-lock"
if /usr/bin/security set-generic-password-partition-list \
    -s dev.joshuarli.vault.security-harness \
    -a "$FILE_LOCK_ACCOUNT" -S '' -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN" >/dev/null; then
    "$BIN" verify-file-lock "$RUN_ID" "$KEYCHAIN"
else
    printf '%s\n' 'file_partition_list_command=failed' >&2
    exit 1
fi

FILE_PRESENCE_ACCOUNT="vault-harness.$RUN_ID.file-user-presence"
"$BIN" verify-file-user-presence "$RUN_ID" "$KEYCHAIN" before-lock
if /usr/bin/security set-generic-password-partition-list \
    -s dev.joshuarli.vault.security-harness \
    -a "$FILE_PRESENCE_ACCOUNT" -S '' -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN" >/dev/null; then
    "$BIN" verify-file-user-presence "$RUN_ID" "$KEYCHAIN" after-lock
else
    printf '%s\n' 'file_user_presence_partition_list_command=failed' >&2
    exit 1
fi

if [ "$MODE" = --gate ] || [ "$MODE" = --interactive ]; then
    IDENTITIES=$(security find-identity -v -p codesigning 2>&1 || true)
    IDENTITY=$(printf '%s\n' "$IDENTITIES" | awk '
        /^[[:space:]]*[0-9]+\)/ {
            hash = $2
            if ($0 ~ /"Apple Development:/ && apple_development == "") apple_development = hash
            if ($0 ~ /"Developer ID Application:/ && developer_id == "") developer_id = hash
            if ($0 ~ /"Vault Signing"/ && vault == "") vault = hash
        }
        END {
            if (apple_development != "") print apple_development
            else if (developer_id != "") print developer_id
            else if (vault != "") print vault
        }
    ')
    case "$IDENTITY" in
        *[!0-9A-Fa-f]*|'') IDENTITY= ;;
    esac
    if [ -n "$IDENTITY" ]; then
        IDENTITY_RUN_ID=$(uuidgen | tr '[:upper:]' '[:lower:]' | tr -d '-')
        IDENTITY_RUN_IDS="$IDENTITY_RUN_IDS $IDENTITY_RUN_ID"
        cp "$BIN" "$IDENTITY_BIN"
        codesign --force --sign "$IDENTITY" --timestamp=none "$IDENTITY_BIN"
        printf 'attempt=existing-identity:%s\n' "$IDENTITY"
        codesign --display --verbose=2 "$IDENTITY_BIN" 2>&1 | sed -n '1,8p'
        "$IDENTITY_BIN" suite "$IDENTITY_RUN_ID" "$KEYCHAIN"
        "$BIN" cross-identity-read "$IDENTITY_RUN_ID"
        if [ "$MODE" = --interactive ]; then
            INTERACTIVE_BIN=$IDENTITY_BIN
            INTERACTIVE_RUN_ID=$IDENTITY_RUN_ID
        fi
    else
        printf '%s\n' 'attempt=existing-identity skipped: security find-identity -v -p codesigning reported no valid Vault Signing, Developer ID Application, or Apple Development identity'
    fi

    PROFILE_COUNT=0
    for profile_dir in \
        "$HOME/Library/MobileDevice/Provisioning Profiles" \
        "$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"; do
        if [ -d "$profile_dir" ]; then
            for profile in "$profile_dir"/*.provisionprofile; do
                if [ -f "$profile" ]; then
                    PROFILE_COUNT=$((PROFILE_COUNT + 1))
                fi
            done
        fi
    done
    if [ "$PROFILE_COUNT" -eq 0 ]; then
        printf '%s\n' 'attempt=app-like-profile skipped: no installed .provisionprofile found in the standard per-user Xcode profile directories'
        printf '%s\n' 'prerequisite=existing provisioning profile authorizing the signing identity and macOS application identifier'
    elif [ -z "$IDENTITY" ]; then
        printf 'attempt=app-like-profile skipped: found %s profile file(s), but security find-identity -v -p codesigning reported no valid identity to match them\n' "$PROFILE_COUNT"
    else
        IDENTITY_TEAM=$(codesign --display --verbose=4 "$IDENTITY_BIN" 2>&1 | sed -n 's/^TeamIdentifier=//p')
        PROFILE_TEMP_INDEX=0
        MATCHED_PROFILE=
        MATCHED_BUNDLE_ID=
        mkdir -p "$PROFILE_SCRATCH"
        for profile_dir in \
            "$HOME/Library/MobileDevice/Provisioning Profiles" \
            "$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"; do
            if [ -d "$profile_dir" ]; then
                for profile in "$profile_dir"/*.provisionprofile; do
                    if [ ! -f "$profile" ]; then
                        continue
                    fi
                    profile_plist="$PROFILE_SCRATCH/profile-$PROFILE_TEMP_INDEX.plist"
                    PROFILE_TEMP_INDEX=$((PROFILE_TEMP_INDEX + 1))
                    if ! security cms -D -i "$profile" > "$profile_plist"; then
                        printf 'profile_decode=failed command=security cms -D -i %s\n' "$profile"
                        continue
                    fi
                    profile_team=$(/usr/libexec/PlistBuddy -c 'Print :TeamIdentifier:0' "$profile_plist" 2>/dev/null || true)
                    profile_app_id=$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:com.apple.application-identifier' "$profile_plist" 2>/dev/null || true)
                    case "$profile_team" in
                        "$IDENTITY_TEAM") ;;
                        *) continue ;;
                    esac
                    case "$profile_app_id" in
                        *.*) app_id_prefix=${profile_app_id%%.*}; app_suffix=${profile_app_id#*.} ;;
                        *) continue ;;
                    esac
                    case "$app_id_prefix" in
                        *[!A-Za-z0-9]*) continue ;;
                    esac
                    if [ -z "$app_id_prefix" ]; then
                        continue
                    fi
                    case "$app_suffix" in
                        '*') bundle_id=dev.joshuarli.vault-security-harness ;;
                        *\*) bundle_prefix=${app_suffix%\*}; bundle_id="${bundle_prefix}vault-security-harness" ;;
                        *) bundle_id=$app_suffix ;;
                    esac
                    private_access_group="$app_id_prefix.$bundle_id"
                    case "$bundle_id:$private_access_group" in
                        *[!A-Za-z0-9.:-]*|:*) continue ;;
                    esac
                    MATCHED_PROFILE=$profile
                    MATCHED_BUNDLE_ID=$bundle_id
                    MATCHED_PRIVATE_ACCESS_GROUP=$private_access_group
                    break 2
                done
            fi
        done

        if [ -z "$MATCHED_PROFILE" ]; then
            printf 'attempt=app-like-profile parked: no installed profile matched TeamIdentifier %s and a macOS application identifier\n' "$IDENTITY_TEAM"
        else
            printf 'attempt=minimal-app-like-bundle profile-present team=%s bundle-id=%s private-access-group=%s\n' "$IDENTITY_TEAM" "$MATCHED_BUNDLE_ID" "$MATCHED_PRIVATE_ACCESS_GROUP"
            mkdir -p "$APP/Contents/MacOS"
            cp "$IDENTITY_BIN" "$APP_BIN"
            cp "$MATCHED_PROFILE" "$APP/Contents/embedded.provisionprofile"
            cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CFBundleExecutable</key><string>vault-security-harness</string>
<key>CFBundleIdentifier</key><string>$MATCHED_BUNDLE_ID</string>
<key>CFBundleName</key><string>Vault Security Harness</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>1</string>
<key>CFBundleVersion</key><string>1</string>
<key>VaultHarnessPrivateAccessGroup</key><string>$MATCHED_PRIVATE_ACCESS_GROUP</string>
</dict>
</plist>
EOF
            cat > "$PROFILE_SCRATCH/entitlements.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.application-identifier</key><string>${MATCHED_PRIVATE_ACCESS_GROUP}</string>
<key>com.apple.developer.team-identifier</key><string>$IDENTITY_TEAM</string>
</dict>
</plist>
EOF
            plutil -lint "$APP/Contents/Info.plist" "$PROFILE_SCRATCH/entitlements.plist"
            if codesign --force --sign "$IDENTITY" --entitlements "$PROFILE_SCRATCH/entitlements.plist" --timestamp=none "$APP"; then
                if codesign --verify --strict --verbose=2 "$APP"; then
                    PACKAGE_RUN_ID=$(uuidgen | tr '[:upper:]' '[:lower:]' | tr -d '-')
                    PACKAGE_RUN_IDS="$PACKAGE_RUN_IDS $PACKAGE_RUN_ID"
                    "$APP_BIN" suite "$PACKAGE_RUN_ID" "$KEYCHAIN"
                    "$BIN" cross-identity-read "$PACKAGE_RUN_ID" "$MATCHED_PRIVATE_ACCESS_GROUP"
                    if [ "$MODE" = --interactive ]; then
                        INTERACTIVE_BIN=$APP_BIN
                        INTERACTIVE_RUN_ID=$PACKAGE_RUN_ID
                    fi
                else
                    printf '%s\n' 'attempt=app-like-profile failed command=codesign --verify --strict'
                fi
            else
                printf '%s\n' 'attempt=app-like-profile failed command=codesign --force --sign --entitlements'
            fi
        fi
    fi
fi

if [ "$MODE" = --interactive ]; then
    printf '%s\n' 'interactive=opt-in'
    "$INTERACTIVE_BIN" interactive "$INTERACTIVE_RUN_ID" "$KEYCHAIN"
fi
