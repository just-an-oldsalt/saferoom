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
| A VPN client with its own DNS | Behavior depends on the client. SafeRoom replaces its resolver connections when the network path changes and every 30 seconds, so it follows the VPN's routes after a reconnect. 0.1.3 did not, and could ask a VPN resolver over the wrong interface until the extension restarted. | Test SafeRoom with each VPN client you deploy. Test a VPN disconnect and reconnect. |
| The first lookup of a host listed only by IPv4 address | The system asks for A and AAAA at the same time, and the AAAA answer has no listed address. | List the domain, or list both address families. |

## Failure modes of SafeRoom

SafeRoom fails open. If it has no list, or if it cannot read a packet, it lets the lookup through. The reason is that a DNS outage stops all work on the Mac, and a gap in blocking is easier to detect and to fix.

| Event | Result | Detection |
|---|---|---|
| No list was ever loaded | Every lookup passes. | Jamf extension attribute: `NO LIST`. |
| Downloads fail | The last good list stays in use. | `DEGRADED`, then `STALE` after three refresh intervals. At a `RefreshSeconds` of 300, that is 15 minutes. |
| The hash file changes a few minutes before the list, for example because of CDN caching | SafeRoom rejects the old list for the new hash and keeps the current list. It retries after 1 minute. | A short `DEGRADED` period after each new list. |
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
- It rejects a list whose SHA-256 does not match `ListSHA256URL`. Host the hash file on a different system from the list. An attacker then needs to change both. SafeRoom sends no credentials to the hash file's host, so that file must be readable without them. SafeRoom downloads the list only when the hash file changes. An attacker who controls only the hash file can stop updates or cause rejections, but cannot install a list.
- It keeps the last good list after any rejection.

These rules do not stop a list that adds a few wrong names. The allowlist in the policy fixes such names at once, without a new list.

Lists are not signed. TLS protects a list in transit, and the optional SHA-256 file detects corruption. Neither stops a server under an attacker's control from serving an old list again, or a list of its choice. Host the hash file on a different system from the list, so an attacker needs to change both.

## Secrets

The bearer token is in the MDM profile. macOS stores the proxy configuration in a file that every user on the Mac can read, so any local user can read the token. This is a property of the token method, and SafeRoom cannot prevent it. Use the client certificate method (mTLS) where you can: the private key does not leave the keychain. If you use a token, give it read access to the list and nothing else, and make it easy to revoke.

SafeRoom never logs the token. It removes the query string and the user information from every URL that it logs or reports, because feed URLs often carry a key there.

SafeRoom sends the token or the client certificate only to the host of the list URL. It refuses a redirect to another host.

The `EventAuth` token has the same problem: any local user can read it. A user with the token can send false events, or many events, to the event server. Give that token permission to add events and nothing else. SafeRoom sends it only to `EventURL` and refuses every redirect from that URL.

## Block events

If the policy sets `EventURL`, each block leaves the Mac: the query name, the app that asked, the host name, and the serial number. Tell your users that blocked lookups are reported, where your rules require it. Lookups that SafeRoom does not block are never sent.

The event buffer is in memory and holds at most 10,000 events. A process that causes many blocks can push older events out of the buffer. The next request then reports the count in `dropped`, so the server knows that events are missing.

## The status channel

The app and the extension talk over XPC. Each side reads the code signature of the other, and refuses the connection unless the team ID is the same. Another process on the Mac cannot read the status or start a download. A test with a client that had a different signature was refused.

Each side also requires the exact bundle identifier of the other and a Developer ID certificate, so another app of the same team, or a development build, cannot connect. Any user can ask for a refresh through the app (`SafeRoom --refresh`), but the extension runs at most one manual refresh every 5 minutes, the same as the shortest policy refresh. It logs the user ID and process ID of each request.

## Hostile input

The extension reads untrusted bytes from three places: the list, DNS packets from every app on the Mac, and answers from DNS servers. Two security reviews traced each path, and probed the risky ones with crafted input. Neither found a way to run code or to crash the extension.

The second review found a bypass. Before version 0.1.2, one answer record that the parser could not read made SafeRoom skip the whole answer. A DNS server could add such a record to hide a blocked address or a blocked alias. SafeRoom now skips only the unreadable record and checks the others. The extension is written in Swift, which checks every array index and integer conversion, and it runs sandboxed with the hardened runtime.

The extension also limits the work that hostile input can cause. A list line longer than 4,096 bytes is skipped unread. One client socket can open at most 8 upstream connections. A TCP connection reads more data only after it has passed on the last data. Names in the log have control characters escaped, so a name with a line break cannot forge a log line.

## Who can change the policy

On a Mac that an MDM manages, the app window is read-only. A user cannot change the policy or turn the proxy off from the app.

On a Mac with no MDM, the user can pick the list, set the options, and turn protection on and off in the app (see the README). The app writes this policy into the DNS proxy configuration with the key `ConfiguredBy` set to `app`. An MDM profile never has this key.

The app lets the user edit only when it can tell that no MDM set the policy. Anything that it cannot tell counts as managed, and the window stays read-only. These are the rules:

- If the extension answers, and the policy it runs does not have `ConfiguredBy = app`, the Mac is managed.
- If the app cannot load the proxy configuration, or the extension has not answered yet, the Mac is managed.
- If the configuration that the app loads does not have `ConfiguredBy = app`, the Mac is managed.
- Before the app saves, it loads the configuration again, and it refuses to replace one that does not have `ConfiguredBy = app`.

Never put `ConfiguredBy` in an MDM profile. With `ConfiguredBy = app`, the window offers the editor on a managed Mac.

The behavior on a managed Mac whose app has not seen the MDM configuration yet is not tested. In this case, the extension does not answer, and the app sees no configuration. The window then offers the first-run setup. It is not known whether macOS then refuses the app's configuration or uses it next to the MDM configuration. Test this on a managed Mac before you deploy this version to a fleet.

A token saved in the app has the same problem as a token in a profile: any local user can read it.

A development build also has buttons that turn the proxy on and off on any Mac, and a `-TestPolicy` launch argument that replaces the policy. A fleet build has neither. `make release` builds a fleet build. `make release DEV_CONTROLS=1` builds a development build. Never deploy a development build to a fleet.

## Privacy

SafeRoom logs only blocked lookups. It does not log the other lookups. The log entries are public in the unified log, so that an EDR or a log forwarder can collect them. Any administrator on the Mac can read them.

## Supply chain

The published binaries are signed with the maintainer's personal Developer ID. If that account is revoked, every Mac that runs those binaries stops trusting SafeRoom. The MDM profile approves only SafeRoom's extension, not every extension of the team. To deploy across a fleet, build and sign SafeRoom under your organization's Developer ID, as [building.md](building.md) explains.

## Not tested yet

- The client certificate (mTLS) download. See [mtls-okta.md](mtls-okta.md).
- Deployment through Jamf Pro, including the silent approval of the extension and the delivery of the policy in `VendorData`.
- The Jamf extension attribute, run as root.
- How the proxy behaves after an edit of the profile in Jamf: an immediate restart, or the next start only.
