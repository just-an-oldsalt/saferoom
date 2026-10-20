#!/usr/bin/env bash
# Archive, Developer ID sign, notarize and staple SafeRoom.app.
#
#   tools/release.sh
#
# The identity comes from Config/Identity.xcconfig and Config/signing.local
# (see tools/identity.sh).
#
# ## Why it re-signs by hand instead of `xcodebuild -exportArchive`
#
# Under Xcode 27, xcodebuild cannot see the Apple account the Xcode app is
# signed in with, so an automatic export fails with "No Accounts". A manual
# export then refuses the Developer ID profiles because Xcode manages them.
# Signing the archived app ourselves needs neither: it only needs the
# Developer ID certificate in the keychain and the two profiles on disk.
#
# ## One-time profile setup (and renewal)
#
# In Xcode: Product > Archive, then Distribute App > Custom > Developer ID >
# Export. That creates the "Mac Team Direct Provisioning Profile" profiles
# this script embeds.
#
# ## The entitlement rewrite
#
# Development profiles offer `dns-proxy`. Developer ID profiles offer only
# `dns-proxy-systemextension`. The entitlements files carry the first, so the
# Debug build signs, and this script swaps in the second.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$HERE/tools/identity.sh"
OUT="${OUT:-$HOME/Library/Caches/saferoom/release}"
require_notary_profile
IDENTITY="${IDENTITY:-$(find_identity "Developer ID Application")}"
[[ -n "$IDENTITY" ]] || { echo "no Developer ID Application identity for team $TEAM_ID in the keychain" >&2; exit 1; }
PROFILES="$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"
ARCHIVE="$OUT/SafeRoom.xcarchive"
APP="$OUT/SafeRoom.app"
SYSEXT="$APP/Contents/Library/SystemExtensions/$EXT_ID.systemextension"

# Path of the newest profile with this exact name.
profile_named() {
    local want="$1" best="" best_date=0 p name date
    for p in "$PROFILES"/*.provisionprofile; do
        security cms -D -i "$p" > "$OUT/p.plist" 2>/dev/null || continue
        name=$(/usr/libexec/PlistBuddy -c "Print :Name" "$OUT/p.plist")
        [[ "$name" == "$want" ]] || continue
        date=$(date -j -f "%a %b %d %T %Z %Y" \
            "$(/usr/libexec/PlistBuddy -c 'Print :CreationDate' "$OUT/p.plist")" +%s)
        if (( date > best_date )); then best="$p"; best_date=$date; fi
    done
    [[ -n "$best" ]] || { echo "no profile named: $want (see header of $0)" >&2; exit 1; }
    echo "$best"
}

# Re-sign one bundle with its current entitlements, rewritten for Developer ID.
resign() {
    local bundle="$1" profile="$2" ents="$OUT/$(basename "$1").entitlements"
    cp "$profile" "$bundle/Contents/embedded.provisionprofile"
    codesign -d --entitlements - --xml "$bundle" > "$ents" 2>/dev/null
    plutil -convert xml1 "$ents"
    sed -i '' 's#<string>dns-proxy</string>#<string>dns-proxy-systemextension</string>#' "$ents"
    /usr/libexec/PlistBuddy -c "Delete :com.apple.security.get-task-allow" "$ents" 2>/dev/null || true
    codesign --force --timestamp --options runtime \
        --entitlements "$ents" --sign "$IDENTITY" "$bundle"
}

cd "$HERE"
xcodegen generate >/dev/null
rm -rf "$ARCHIVE" "$APP" "$OUT/SafeRoom.zip"
mkdir -p "$OUT"

# DEV_CONTROLS=1 keeps the app's proxy buttons and -TestPolicy argument, for
# testing without MDM. Never ship such a build to a fleet: a user could turn
# the proxy off from the app window.
EXTRA=()
if [[ "${DEV_CONTROLS:-0}" == 1 ]]; then
    echo "==> DEV_CONTROLS=1: development build, not for fleet use"
    EXTRA=('SWIFT_ACTIVE_COMPILATION_CONDITIONS=$(inherited) SAFEROOM_DEV_CONTROLS')
fi

echo "==> archive"
xcodebuild archive -quiet \
    -project SafeRoom.xcodeproj -scheme SafeRoom \
    -destination 'generic/platform=macOS' \
    -archivePath "$ARCHIVE" ${EXTRA[@]+"${EXTRA[@]}"}

echo "==> sign with $IDENTITY"
ditto "$ARCHIVE/Products/Applications/SafeRoom.app" "$APP"
resign "$SYSEXT" "$(profile_named "Mac Team Direct Provisioning Profile: $EXT_ID")"
resign "$APP" "$(profile_named "Mac Team Direct Provisioning Profile: $APP_ID")"
codesign --verify --deep --strict "$APP"

echo "==> notarize with profile $NOTARY_PROFILE"
ditto -c -k --keepParent "$APP" "$OUT/SafeRoom.zip"
xcrun notarytool submit "$OUT/SafeRoom.zip" --keychain-profile "$NOTARY_PROFILE" --wait
xcrun stapler staple "$APP"

echo "==> checks"
spctl --assess --type execute --verbose "$APP"
codesign -d --entitlements - "$SYSEXT" 2>/dev/null | grep -A2 networkextension

echo
echo "Release app: $APP"
echo "Install: cp -R \"$APP\" /Applications/ and launch it once."
