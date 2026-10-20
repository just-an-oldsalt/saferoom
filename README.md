# SafeRoom

SafeRoom is a macOS system extension that blocks DNS lookups for domains on a threat intelligence list. It answers NXDOMAIN (the DNS "this name does not exist" reply) for each listed domain. All other queries go to the resolver that the Mac already uses.

SafeRoom targets lists of 100,000 to 250,000 domains, which is more than most commercial blocking products accept. The whole list stays in memory as a compact hash table.

An MDM (Jamf or any other) deploys and configures SafeRoom. The policy sets where the list comes from: an HTTPS URL or a local file.

The name comes from Dungeon Crawler Carl. In the dungeon, a safe room is the one place where nothing can attack you.

## Status

This project is in early development. The proxy blocks domains and address ranges, over UDP and TCP, and it logs each block with the app that asked. It downloads its list from an HTTPS URL with a bearer token, rejects suspect lists, and keeps the last good list on any failure. On a test Mac, a list of 250,000 domains uses 2.2 MB of memory, and a lookup takes about 140 nanoseconds.

The app shows the extension's status, and `SafeRoom --jamf` reports health to Jamf inventory. Sample MDM profiles and a signed installer package are ready. Deployment through Jamf Pro and the client certificate download are not tested yet. The client certificate (mTLS) download is built but not tested.

## Documentation

- [docs/list-format.md](docs/list-format.md): the blocklist format.
- [docs/mdm.md](docs/mdm.md): the MDM policy keys and the update rules.
- [docs/mtls-okta.md](docs/mtls-okta.md): the client certificate download, and its open risks.
- [docs/threat-model.md](docs/threat-model.md): what SafeRoom stops, what it does not stop, and how it fails.
- [mdm/](mdm/): the MDM profiles and the Jamf extension attribute.

## Requirements

- macOS 15 or later.
- Xcode 27 and [XcodeGen](https://github.com/yonaskolb/XcodeGen).

## Build

```sh
make test      # SafeRoomCore unit tests. Needs no signing.
make open      # Generate SafeRoom.xcodeproj and open it in Xcode.
make release   # Archive, sign with Developer ID, notarize and staple.
make package   # Signed, notarized installer package for MDM.
make bench     # The list engine at several sizes (see docs/performance.md).
```

`make release` needs a Developer ID certificate, the Developer ID provisioning profiles, and a `notarytool` keychain profile. To build under your organization, change the two lines in `Config/Identity.xcconfig` and follow [docs/building.md](docs/building.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
