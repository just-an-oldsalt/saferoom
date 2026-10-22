# Sourced by the release scripts. Reads the build identity from
# Config/Identity.xcconfig and local signing settings from
# Config/signing.local (not in git), and finds this team's Developer ID
# certificates in the keychain. Nothing personal is written in the repo.

IDENTITY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEAM_ID=$(sed -n 's/^SAFEROOM_TEAM_ID *= *//p' "$IDENTITY_ROOT/Config/Identity.xcconfig")
APP_ID=$(sed -n 's/^SAFEROOM_APP_ID *= *//p' "$IDENTITY_ROOT/Config/Identity.xcconfig")
EXT_ID="$APP_ID.dnsproxy"
[[ -n "$TEAM_ID" && -n "$APP_ID" ]] || { echo "Config/Identity.xcconfig must set SAFEROOM_TEAM_ID and SAFEROOM_APP_ID" >&2; exit 1; }

# shellcheck source=/dev/null
[[ -f "$IDENTITY_ROOT/Config/signing.local" ]] && source "$IDENTITY_ROOT/Config/signing.local"

# The keychain identity named "<kind>: <anything> (<team>)", or empty.
# kind: "Developer ID Application" or "Developer ID Installer".
find_identity() {
    security find-identity -v | sed -n "s/.*\"\($1: .* ($TEAM_ID)\)\".*/\1/p" | head -1
}

require_notary_profile() {
    if [[ -z "${NOTARY_PROFILE:-}" ]]; then
        echo "Set NOTARY_PROFILE in Config/signing.local (see Config/signing.local.example)" >&2
        exit 1
    fi
}

# The developer-ID code requirement for one bundle ID, for scripts that
# check a signature (the same rule as Identity.requirement in Swift).
requirement_for() {
    printf '%s' "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"$TEAM_ID\" and identifier \"$1\""
}

# Copies a file with __TEAM_ID__, __APP_ID__, __EXT_ID__, __REQUIREMENT__
# (the app's) and __EXT_REQUIREMENT__ (the extension's) filled in.
render() {
    local requirement ext_requirement
    requirement=$(requirement_for "$APP_ID" | sed 's/[&|\\]/\\&/g')
    ext_requirement=$(requirement_for "$EXT_ID" | sed 's/[&|\\]/\\&/g')
    sed -e "s|__TEAM_ID__|$TEAM_ID|g" -e "s|__APP_ID__|$APP_ID|g" -e "s|__EXT_ID__|$EXT_ID|g" \
        -e "s|__EXT_REQUIREMENT__|$ext_requirement|g" \
        -e "s|__REQUIREMENT__|$requirement|g" "$1" > "$2"
}
