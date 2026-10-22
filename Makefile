# SafeRoom. The .xcodeproj is generated from project.yml and not committed,
# so `make open` is the way in.
.PHONY: open project test app release package icon bench clean

## Generate the project and open it.
open: project
	open SafeRoom.xcodeproj

project:
	xcodegen generate

## SafeRoomCore tests. Need no signing and no project.
#
# The scratch path is outside the repo because ~/Documents is iCloud-synced,
# and synced files carry FinderInfo that codesign refuses on test bundles.
SPM_SCRATCH ?= $(HOME)/Library/Caches/saferoom/spm

test:
	swift test --scratch-path "$(SPM_SCRATCH)"

## Debug build of app and extension (signed with Apple Development).
app: project
	xcodebuild -project SafeRoom.xcodeproj -scheme SafeRoom \
		-destination 'platform=macOS' -allowProvisioningUpdates build

## Developer ID archive, notarize and staple. Identity: Config/Identity.xcconfig
## and Config/signing.local.

## DEV_CONTROLS=1 keeps the app's proxy buttons and -TestPolicy (not for fleets).
DEV_CONTROLS ?= 0

release:
	DEV_CONTROLS="$(DEV_CONTROLS)" tools/release.sh

## Installer package for MDM, from the release app.
package:
	tools/package.sh

## The scale benchmark behind docs/performance.md: one process per size.
BENCH_SIZES ?= 250000:1692 1000000:1692 3000000:1692 5000000:1692 250000:100000 250000:1000000

## Redraw the app icon from tools/make-icon.swift.
icon:
	tools/icon.sh

bench:
	swift build -c release --package-path Benchmarks --scratch-path "$(HOME)/Library/Caches/saferoom/bench"
	@for s in $(BENCH_SIZES); do \
		"$$(swift build -c release --package-path Benchmarks --scratch-path "$(HOME)/Library/Caches/saferoom/bench" --show-bin-path)/bench" $${s%%:*} $${s##*:}; \
	done

clean:
	rm -rf SafeRoom.xcodeproj .build
