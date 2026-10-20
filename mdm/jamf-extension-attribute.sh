#!/bin/sh
# Jamf Pro extension attribute: SafeRoom health.
#
# Use the copy that tools/package.sh writes to the release folder: it has
# __REQUIREMENT__ filled in with this build's team and bundle ID.
#
# Data type: String. Jamf runs this as root during inventory. It prints one
# line, for example:
#
#   <result>OK: 234910 domains, 1692 ranges, list checked 2026-10-19 21:41, version 0.1.1 (14)</result>
#
# The first word is the state, for smart groups:
#   OK            a list is loaded and the last check succeeded
#   DEGRADED      recent checks failed; the list in use is not stale yet
#   STALE         no successful check for 3 refresh intervals
#   NO LIST       no list is loaded; every query passes (fail-open)
#   NOT RUNNING   the extension or the proxy does not answer
#   NOT INSTALLED the app is missing
#   TAMPERED      the app at the expected path is not SafeRoom as signed by
#                 its developer, so its output is not trusted
#
# The signature check stops a local admin from replacing the app with a
# script that prints "OK". /usr/bin/codesign is protected by SIP.

BUNDLE="/Applications/SafeRoom.app"
# Developer ID certificate, our team, the exact app. A development build fails.
REQUIREMENT='__REQUIREMENT__'

if [ ! -e "$BUNDLE" ]; then
    echo "<result>NOT INSTALLED</result>"
    exit 0
fi
if ! /usr/bin/codesign --verify --deep --strict -R="$REQUIREMENT" "$BUNDLE" >/dev/null 2>&1; then
    echo "<result>TAMPERED: the code signature of $BUNDLE does not match SafeRoom</result>"
    exit 0
fi
"$BUNDLE/Contents/MacOS/SafeRoom" --jamf
