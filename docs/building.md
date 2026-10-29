# Build SafeRoom under your organization

This page explains how to build, sign, and package SafeRoom with your own Apple Developer account. Do this before you deploy SafeRoom across a fleet. The published binaries are signed by the maintainer, and your fleet must not depend on someone else's account.

## What you need

- A Mac with macOS 15 or later, Xcode 27, and [XcodeGen](https://github.com/yonaskolb/XcodeGen).
- An Apple Developer Program membership for your organization.
- In the keychain of that Mac: a "Developer ID Application" certificate and a "Developer ID Installer" certificate for your team.
- Xcode signed in to that team, under Settings > Apple Accounts.

## Steps

1. In `Config/Identity.xcconfig`, set `SAFEROOM_TEAM_ID` to your team ID and `SAFEROOM_APP_ID` to a bundle ID that you own, for example `com.example.saferoom`. The code, the entitlements, the scripts, and the MDM files all derive their names from these two lines.
2. Create a notarytool keychain profile:

   ```sh
   xcrun notarytool store-credentials saferoom-notary --apple-id <apple-id> --team-id <team-id>
   ```

3. Copy `Config/signing.local.example` to `Config/signing.local`, and set `NOTARY_PROFILE` to the profile name from step 2. Git ignores this file.
4. Create the Developer ID provisioning profiles once. In Xcode, run `make open`, choose Product > Archive, then Distribute App > Custom > Developer ID > Export. When the profiles expire, do this step again.
5. Build:

   ```sh
   make test
   make release package
   ```

The release folder is `~/Library/Caches/saferoom/release`. It holds the signed and notarized package. Its `mdm/` folder holds the two profiles and the Jamf extension attribute, with your team ID, bundle IDs, and code signature requirements filled in. Upload those copies, not the files in this repository, which hold placeholders.

`make package` stops with an error if a rendered file still holds a placeholder, or if the profile's `ProviderDesignatedRequirement` does not match the extension in the package. It shows a warning if the profile still holds the sample policy values. You can replace those values in the profile or in your MDM.

The release scripts find your certificates in the keychain by team ID, so no name or account is written in the repository.

## Development builds

`make release DEV_CONTROLS=1` builds a version with buttons that turn the proxy on and off and with a `-TestPolicy` launch argument. Use it only on test Macs. A fleet build has neither. On a managed Mac, a fleet build is read-only. On a Mac with no MDM, the user can pick the list in the app (see the threat model, "Who can change the policy").

A proxy configuration written by an earlier development build has no `ConfiguredBy` key, so the window shows that Mac as managed. To fix it, click Remove in a development build's window, or delete SafeRoom in System Settings > Network > Filters & Proxies. A fleet build then shows the first run. The dev controls now add `ConfiguredBy = app` unless the test policy sets the key.

Debug builds accept `-SampleStatus YES` and `-SampleAccess firstRun`, `on`, or `off`, which show made-up data and the matching window mode, with no extension.
