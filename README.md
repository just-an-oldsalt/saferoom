# SafeRoom

SafeRoom is a macOS system extension that blocks DNS lookups for domains on a threat intelligence list. It answers NXDOMAIN (the DNS "this name does not exist" reply) for each listed domain. All other queries go to the resolver that the Mac already uses.

SafeRoom targets lists of 100,000 to 250,000 domains, which is more than most commercial blocking products accept. The whole list stays in memory as a compact hash table.

An MDM (Jamf or any other) deploys and configures SafeRoom. The policy sets where the list comes from: an HTTPS URL or a local file.

The name comes from Dungeon Crawler Carl. In the dungeon, a safe room is the one place where nothing can attack you.

## Status

This project is in early development. Phase 0 is complete: the app and an empty DNS proxy build, sign with Developer ID, and pass notarization. The extension does not block anything yet.

## Requirements

- macOS 15 or later.
- Xcode 27 and [XcodeGen](https://github.com/yonaskolb/XcodeGen).

## Build

```sh
make test      # SafeRoomCore unit tests. Needs no signing.
make open      # Generate SafeRoom.xcodeproj and open it in Xcode.
make release   # Archive, sign with Developer ID, notarize and staple.
```

`make release` needs a Developer ID certificate, the Developer ID provisioning profiles, and a `notarytool` keychain profile. The header of `tools/release.sh` explains how to create them.

## License

Apache License 2.0. See [LICENSE](LICENSE).
