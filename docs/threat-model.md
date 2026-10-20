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

## A bad list

A feed can be wrong by mistake, or an attacker can change it. A list that blocks too much stops business work on every Mac. SafeRoom limits the damage in these ways:

- It never blocks the built-in names (Apple, iCloud, Jamf Cloud, Okta), the `NeverBlockHosts` from the policy, or the host of the list URL. A bad list therefore cannot stop the fix from arriving.
- It can reject a list whose entry count changes by more than `MaxChangePercent`. The rule is off by default. A rejection stays until an administrator changes the profile, so a legitimate change to the feed would stop every Mac from updating.
- It rejects an empty list as a replacement for a list with entries.
- It rejects a list whose SHA-256 does not match `ListSHA256URL`. Host the hash file on a different system from the list. An attacker then needs to change both. SafeRoom sends no credentials to the hash file's host, so that file must be readable without them.
- It keeps the last good list after any rejection.

These rules do not stop a list that adds a few wrong names. The allowlist in the policy fixes such names at once, without a new list.

## Secrets

The bearer token is in the MDM profile. An administrator on a managed Mac can read the profile. Give the token read access to the list and nothing else.

SafeRoom never logs the token. It removes the query string and the user information from every URL that it logs or reports, because feed URLs often carry a key there.

SafeRoom sends the token or the client certificate only to the host of the list URL. It refuses a redirect to another host.

## The status channel

The app and the extension talk over XPC. Each side reads the code signature of the other, and refuses the connection unless the team ID is the same. Another process on the Mac cannot read the status or start a download. A test with a client that had a different signature was refused.

## Development controls

A development build of the app has buttons that turn the proxy on and off, and a `-TestPolicy` launch argument that replaces the policy. A fleet build has neither, so a user cannot turn the proxy off from the app. `make release` builds a fleet build. `make release DEV_CONTROLS=1` builds a development build. Never deploy a development build to a fleet.

## Privacy

SafeRoom logs only blocked lookups. It does not log the other lookups. The log entries are public in the unified log, so that an EDR or a log forwarder can collect them. Any administrator on the Mac can read them.

## Supply chain

The app and the extension are signed with a personal Developer ID (team `346JJCHZP7`). The MDM profile trusts that team for the system extension. Before you deploy SafeRoom across a fleet, build and sign it under your organization's Developer ID, and change the team ID in the profile.

## Not tested yet

- The client certificate (mTLS) download. See [mtls-okta.md](mtls-okta.md).
- Deployment through Jamf Pro, including the silent approval of the extension and the delivery of the policy in `VendorData`.
- The Jamf extension attribute, run as root.
- How the proxy behaves after an edit of the profile in Jamf: an immediate restart, or the next start only.
