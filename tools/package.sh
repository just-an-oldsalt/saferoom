#!/usr/bin/env bash
# Build SafeRoom.pkg for MDM deployment, from the notarized app that
# tools/release.sh produced.
#
#   tools/package.sh
#
# The package installs SafeRoom.app in /Applications. Its post-install script
# runs `SafeRoom --activate`, which submits the system extension. With the MDM
# profile (mdm/saferoom.mobileconfig) installed first, macOS approves the
# extension with no prompt.
#
# INSTALLER_IDENTITY: the "Developer ID Installer" identity that signs the
# package, found in the keychain by team (Config/Identity.xcconfig). Set it
# to an empty string for an unsigned package: Jamf accepts that for its own
# installs, but Gatekeeper refuses it on double-click.
#
# The MDM profiles and the Jamf script are rendered with this build's
# identity into $OUT/mdm/, ready to upload.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${OUT:-$HOME/Library/Caches/saferoom/release}"
APP="$OUT/SafeRoom.app"
source "$HERE/tools/identity.sh"
INSTALLER_IDENTITY="${INSTALLER_IDENTITY-$(find_identity "Developer ID Installer")}"
[[ -z "$INSTALLER_IDENTITY" ]] || require_notary_profile
VERSION=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$APP/Contents/Info.plist")
BUILD=$(/usr/libexec/PlistBuddy -c "Print :CFBundleVersion" "$APP/Contents/Info.plist")
PKG="$OUT/SafeRoom-$VERSION-$BUILD.pkg"

[[ -d "$APP" ]] || { echo "no $APP: run tools/release.sh first" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/root/Applications" "$WORK/scripts"
ditto "$APP" "$WORK/root/Applications/SafeRoom.app"

cat > "$WORK/scripts/postinstall" <<'POST'
#!/bin/sh
# Submit the system extension. macOS takes the request from an app in a user
# session, so run it as the user at the console. With the MDM profile in
# place, no prompt appears.
#
# With nobody logged in, the request is tried as root, which can fail. The
# app also submits the request each time it opens. A failure here does not
# fail the install.
#
# Absolute paths only, and the app's signature is checked first, so nothing
# in the environment can substitute another program.
PATH=/usr/bin:/bin:/usr/sbin:/sbin
BUNDLE=/Applications/SafeRoom.app
# Developer ID certificate, our team, the exact app. A development build fails.
REQUIREMENT='__REQUIREMENT__'
if ! /usr/bin/codesign --verify --deep --strict -R="$REQUIREMENT" "$BUNDLE"; then
    echo "SafeRoom postinstall: signature check failed; not activating"
    exit 0
fi
# The folder for a local list. Only root may write it; the extension refuses
# a list file there that anyone else can write.
/bin/mkdir -p "/Library/Application Support/SafeRoom"
/usr/sbin/chown root:wheel "/Library/Application Support/SafeRoom"
/bin/chmod 755 "/Library/Application Support/SafeRoom"
APP="$BUNDLE/Contents/MacOS/SafeRoom"
USER_NAME=$(/usr/bin/stat -f %Su /dev/console)
if [ -n "$USER_NAME" ] && [ "$USER_NAME" != "root" ] && [ "$USER_NAME" != "loginwindow" ]; then
    USER_ID=$(/usr/bin/id -u "$USER_NAME")
    /bin/launchctl asuser "$USER_ID" /usr/bin/sudo -u "$USER_NAME" "$APP" --activate
else
    "$APP" --activate
fi
echo "SafeRoom postinstall: --activate exited $?"
exit 0
POST
render "$WORK/scripts/postinstall" "$WORK/scripts/postinstall.rendered"
mv "$WORK/scripts/postinstall.rendered" "$WORK/scripts/postinstall"
chmod +x "$WORK/scripts/postinstall"

# Keep the bundle where we put it: no relocation to a copy elsewhere.
pkgbuild --analyze --root "$WORK/root" "$WORK/components.plist" >/dev/null
/usr/libexec/PlistBuddy -c "Add :0:BundleIsRelocatable bool false" "$WORK/components.plist"

SIGN=()
[[ -n "$INSTALLER_IDENTITY" ]] && SIGN=(--sign "$INSTALLER_IDENTITY")
pkgbuild --root "$WORK/root" --component-plist "$WORK/components.plist" \
    --scripts "$WORK/scripts" --identifier "$APP_ID.pkg" \
    --version "$VERSION.$BUILD" --install-location / ${SIGN[@]+"${SIGN[@]}"} "$PKG"

if [[ -n "$INSTALLER_IDENTITY" ]]; then
    xcrun notarytool submit "$PKG" --keychain-profile "$NOTARY_PROFILE" --wait
    xcrun stapler staple "$PKG"
fi
mkdir -p "$OUT/mdm"
for f in saferoom.mobileconfig saferoom-bypass-controls.mobileconfig jamf-extension-attribute.sh; do
    render "$HERE/mdm/$f" "$OUT/mdm/$f"
done
plutil -lint "$OUT/mdm/"*.mobileconfig >/dev/null

# Every placeholder must be filled in.
if grep -n '__[A-Z_]*__' "$OUT/mdm/"*; then
    echo "error: unfilled placeholders in $OUT/mdm/" >&2; exit 1
fi
# The profile's ProviderDesignatedRequirement must match the extension that
# ships in this package, or the proxy never starts on the fleet.
EXT_REQ=$(plutil -extract PayloadContent.1.ProviderDesignatedRequirement raw "$OUT/mdm/saferoom.mobileconfig")
EXT_BUNDLE="$APP/Contents/Library/SystemExtensions/$EXT_ID.systemextension"
if ! codesign --verify -R="$EXT_REQ" "$EXT_BUNDLE"; then
    echo "error: ProviderDesignatedRequirement does not match $EXT_BUNDLE" >&2; exit 1
fi
# The sample policy values must be replaced before the profile is uploaded.
# Not fatal: many admins edit ProviderConfiguration in the MDM instead.
if grep -nE 'example\.com|REPLACE-WITH|yourcompany|example-partner' "$OUT/mdm/saferoom.mobileconfig"; then
    echo "WARNING: $OUT/mdm/saferoom.mobileconfig still holds the sample policy values above." >&2
    echo "WARNING: Replace them, here or in your MDM, before you deploy it." >&2
fi
echo "Package: $PKG"
echo "MDM files: $OUT/mdm/"
