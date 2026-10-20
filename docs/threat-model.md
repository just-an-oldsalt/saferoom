# Threat model

This page states what SafeRoom stops, what it does not stop, and what can go wrong with SafeRoom itself. Read it before you rely on SafeRoom as a control.

## What SafeRoom stops

If a process on the Mac asks plain DNS for a listed name, SafeRoom answers NXDOMAIN. This applies to every process that sends DNS on port 53, over UDP or TCP. The tests caught lookups from the system resolver, from `dig`, and from `dscacheutil`.

SafeRoom also stops these indirect paths:

- A name that is an alias (CNAME) for a listed name.
- An HTTPS or SVCB record whose target is a listed name.
- An answer that holds an address in a listed range, including the `ipv4hint` and `ipv6hint` values of HTTPS records.
- After such an answer, every record type for that name, for five minutes.

Each block goes to the unified log with the name, the rule, and the signing ID of the app that asked.

## What SafeRoom does not stop

| Path | Why it passes | What to do |
|---|---|---|
| DNS over HTTPS, TLS, or QUIC from an app | The lookup is encrypted and does not use port 53. | Deploy `mdm/saferoom-bypass-controls.mobileconfig` for the browsers. For other apps, add the domains of public DoH services to the list, for example `dns.google` and `cloudflare-dns.com`. |
| DNS over HTTPS or TLS sent to an IP address | No name is looked up, so a list of DoH domains does not help. DoT uses port 853. | Block outbound 853, and 443 to known public resolver addresses, with a firewall or EDR. Restrict which apps users can install. |
| A browser outside the bypass profile | The profile covers Chrome, Edge, Brave, and Firefox. Arc, Opera, Vivaldi, and others have their own DoH settings. | Add a payload for each browser you allow, or block the others. |
| iCloud Private Relay | Safari lookups go through Apple's relay. | The bypass-controls profile turns Private Relay off, but only on a supervised Mac (Automated Device Enrollment). On other Macs, users can turn it on. |
| A connection to an IP address | No DNS lookup happens. | Use a firewall or an EDR network control for address blocks. |
| An entry in `/etc/hosts` | The system resolver answers from the file without DNS. | Only an administrator can edit the file. Monitor it with your EDR. |
| Another encrypted DNS profile | A `com.apple.dnsSettings.managed` profile from another tool sends system lookups encrypted. | Do not deploy both. |
| A VPN client with its own DNS | Behavior depends on the client. | Test SafeRoom with each VPN client you deploy. |
| The first lookup of a host listed only by IPv4 address | The system asks for A and AAAA at the same time, and the AAAA answer has no listed address. | List the domain, or list both address families. |

## Failure modes of SafeRoom

SafeRoom fails open. If it has no list, or if it cannot read a packet, it lets the lookup through. The reason is that a DNS outage stops all work on the Mac, and a gap in blocking is easier to detect and to fix.

| Event | Result | Detection |
|---|---|---|
| No list was ever loaded | Every lookup passes. | Jamf extension attribute: `NO LIST`. |
| Downloads fail | The last good list stays in use. | `DEGRADED`, then `STALE` after three refresh intervals. |
| The extension crashes | macOS restarts it. Lookups in the gap fail, and blocking starts again from the cache in milliseconds. | `provider` log category: a new `startProxy`. |
| An administrator stops or removes the extension | The profile marks the extension as not removable, but root can still stop the process. macOS restarts it. | `NOT RUNNING`, or a new `startProxy` in the log. |
| An administrator replaces the app with a program that reports `OK` to Jamf | The Jamf script checks the code signature of the app before it runs it. | Jamf: `TAMPERED`. |
| An administrator installs an older SafeRoom build | The app refuses to replace the extension with an older version. | The version is in the Jamf result. |

## A bad list

A feed can be wrong by mistake, or an attacker can change it. A list that blocks too much stops business work on every Mac. SafeRoom limits the damage in these ways:

- It never blocks the built-in names (Apple, iCloud, Jamf Cloud, Okta), the `NeverBlockHosts` from the policy, or the host of the list URL. A bad list therefore cannot stop the fix from arriving.
- It can reject a list whose entry count changes by more than `MaxChangePercent`. The rule is off by default. A rejection stays until an administrator changes the profile, so a legitimate change to the feed would stop every Mac from updating.
- It rejects an empty list as a replacement for a list with entries.
- It ignores rules on a single label, like `*.com`, unless the policy sets `AllowTopLevelBlocks`. It rejects address ranges broader than IPv4 `/8` or IPv6 `/16`.
- It rejects a list whose SHA-256 does not match `ListSHA256URL`. Host the hash file on a different system from the list. An attacker then needs to change both. SafeRoom sends no credentials to the hash file's host, so that file must be readable without them.
- It keeps the last good list after any rejection.

These rules do not stop a list that adds a few wrong names. The allowlist in the policy fixes such names at once, without a new list.

Lists are not signed. TLS protects a list in transit, and the optional SHA-256 file detects corruption. Neither stops a server under an attacker's control from serving an old list again, or a list of its choice. Host the hash file on a different system from the list, so an attacker needs to change both.

## Secrets

The bearer token is in the MDM profile. macOS stores the proxy configuration in a file that every user on the Mac can read, so any local user can read the token. This is a property of the token method, and SafeRoom cannot prevent it. Use the client certificate method (mTLS) where you can: the private key does not leave the keychain. If you use a token, give it read access to the list and nothing else, and make it easy to revoke.

SafeRoom never logs the token. It removes the query string and the user information from every URL that it logs or reports, because feed URLs often carry a key there.

SafeRoom sends the token or the client certificate only to the host of the list URL. It refuses a redirect to another host.

## The status channel

The app and the extension talk over XPC. Each side reads the code signature of the other, and refuses the connection unless the team ID is the same. Another process on the Mac cannot read the status or start a download. A test with a client that had a different signature was refused.

Each side also requires the exact bundle identifier of the other and a Developer ID certificate, so another app of the same team, or a development build, cannot connect. Any user can ask for a refresh through the app (`SafeRoom --refresh`), but the extension runs at most one manual refresh every 5 minutes, the same as the shortest policy refresh. It logs the user ID and process ID of each request.

## Hostile input

The extension reads untrusted bytes from three places: the list, DNS packets from every app on the Mac, and answers from DNS servers. Two security reviews traced each path, and probed the risky ones with crafted input. Neither found a way to run code or to crash the extension.

The second review found a bypass. Before version 0.1.2, one answer record that the parser could not read made SafeRoom skip the whole answer. A DNS server could add such a record to hide a blocked address or a blocked alias. SafeRoom now skips only the unreadable record and checks the others. The extension is written in Swift, which checks every array index and integer conversion, and it runs sandboxed with the hardened runtime.

The extension also limits the work that hostile input can cause. A list line longer than 4,096 bytes is skipped unread. One client socket can open at most 8 upstream connections. A TCP connection reads more data only after it has passed on the last data. Names in the log have control characters escaped, so a name with a line break cannot forge a log line.

## Development controls

A development build of the app has buttons that turn the proxy on and off, and a `-TestPolicy` launch argument that replaces the policy. A fleet build has neither, so a user cannot turn the proxy off from the app. `make release` builds a fleet build. `make release DEV_CONTROLS=1` builds a development build. Never deploy a development build to a fleet.

## Privacy

SafeRoom logs only blocked lookups. It does not log the other lookups. The log entries are public in the unified log, so that an EDR or a log forwarder can collect them. Any administrator on the Mac can read them.

## Supply chain

The app and the extension are signed with a personal Developer ID (team `346JJCHZP7`). The team ID appears in the profiles, the Jamf script, the scripts, and the code signature checks. If that personal account is revoked, every Mac stops trusting SafeRoom. The MDM profile approves only SafeRoom's extension, not every extension of the team. Before you deploy SafeRoom across a fleet, build and sign it under your organization's Developer ID, and change the team ID in the profile.

## Not tested yet

- The client certificate (mTLS) download. See [mtls-okta.md](mtls-okta.md).
- Deployment through Jamf Pro, including the silent approval of the extension and the delivery of the policy in `VendorData`.
- The Jamf extension attribute, run as root.
- How the proxy behaves after an edit of the profile in Jamf: an immediate restart, or the next start only.
