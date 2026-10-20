#!/bin/sh
# Jamf Pro extension attribute: SafeRoom health.
#
# Data type: String. Jamf runs this as root during inventory. It prints one
# line, for example:
#
#   <result>OK: 248113 domains, 12 ranges, list checked 2026-10-19 21:41</result>
#
# The first word is the state, for smart groups:
#   OK           a list is loaded and the last check succeeded
#   DEGRADED     recent checks failed; the list in use is not stale yet
#   STALE        no successful check for 3 refresh intervals
#   NO LIST      no list is loaded; every query passes (fail-open)
#   NOT RUNNING  the extension or the proxy does not answer
#   NOT INSTALLED

APP="/Applications/SafeRoom.app/Contents/MacOS/SafeRoom"
if [ ! -x "$APP" ]; then
    echo "<result>NOT INSTALLED</result>"
    exit 0
fi
"$APP" --jamf
