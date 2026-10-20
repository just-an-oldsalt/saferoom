# SafeRoom. The .xcodeproj is generated from project.yml and not committed,
# so `make open` is the way in.
.PHONY: open project test app release package clean

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

## Developer ID archive, notarize and staple.
NOTARY_PROFILE ?= notary-profile

release:
	NOTARY_PROFILE="$(NOTARY_PROFILE)" tools/release.sh

## Installer package for MDM, from the release app.
package:
	NOTARY_PROFILE="$(NOTARY_PROFILE)" tools/package.sh

clean:
	rm -rf SafeRoom.xcodeproj .build
