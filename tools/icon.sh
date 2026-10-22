#!/usr/bin/env bash
# Renders tools/make-icon.swift into the app's asset catalog.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SET="$HERE/App/Assets.xcassets/AppIcon.appiconset"
mkdir -p "$SET"
MASTER=$(mktemp -d)/icon_1024.png
swift "$HERE/tools/make-icon.swift" "$MASTER"
images=""
for size in 16 32 128 256 512; do
    for scale in 1 2; do
        px=$((size * scale))
        name="icon_${size}x${size}@${scale}x.png"
        sips -z "$px" "$px" "$MASTER" --out "$SET/$name" >/dev/null
        images+="    { \"idiom\": \"mac\", \"size\": \"${size}x${size}\", \"scale\": \"${scale}x\", \"filename\": \"$name\" },"$'\n'
    done
done
printf '{\n  "images": [\n%s  ],\n  "info": { "version": 1, "author": "xcode" }\n}\n' "${images%,$'\n'}"$'\n' > "$SET/Contents.json"
printf '{\n  "info": { "version": 1, "author": "xcode" }\n}\n' > "$HERE/App/Assets.xcassets/Contents.json"
echo "icon: $SET"
