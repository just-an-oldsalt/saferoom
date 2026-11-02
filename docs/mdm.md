# MDM policy

An MDM configures SafeRoom with the DNS Proxy payload (`com.apple.dnsProxy.managed`). The payload's `ProviderConfiguration` dictionary holds the SafeRoom policy. This page lists every key.

Do not put the key `ConfiguredBy` in a profile. The SafeRoom app writes it when a user sets the policy on a Mac with no MDM, and the window uses it to decide whether the user can edit the policy.

SafeRoom ignores keys that it does not know. If a value has the wrong type or an invalid form, SafeRoom uses the default value for that key, and logs the value and the reason in the `provider` category. A typing error in a profile never stops the proxy.

## Deploy with Jamf Pro

You need three files from this repository:

- `SafeRoom-<version>.pkg`, built with `make release package`. Do not set `DEV_CONTROLS=1` for a fleet build (see the threat model).
- `saferoom.mobileconfig`, which approves the extension and holds the policy.
- `saferoom-bypass-controls.mobileconfig`, which turns off browser DNS over HTTPS and iCloud Private Relay.
- `jamf-extension-attribute.sh`, which reports SafeRoom health to Jamf inventory.

Take the profiles and the script from the `mdm/` folder next to the package in the release folder (`~/Library/Caches/saferoom/release/mdm/`). `make package` fills in the team ID, the bundle IDs, and the code signature requirements there. The copies in this repository hold placeholders. A profile from the repository does not install, and the repository copy of the extension attribute reports `TAMPERED` on every Mac.

The DNS Proxy payload must have the `ProviderDesignatedRequirement` key. Its value is the code signature requirement of the extension, not of the app. Without it, the proxy never starts, and `nesessionmanager` logs "missing designated requirement". A restart does not fix this. Apple's [schema for the payload](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.dnsProxy.managed.yaml) lists the key, but Apple's web page for the payload does not. `make package` writes the key and makes sure that it matches the extension in the package. If you write the profile yourself, get the value with this command:

```sh
codesign -d -r- /Applications/SafeRoom.app/Contents/Library/SystemExtensions/*.systemextension
```

Remove the `designated =>` prefix, and write `exists` where the output shows the comment `/* exists */`.

Do the steps in this order. With the profile installed first, macOS approves the extension with no prompt. A test Mac that got the package first and the profile after it also worked: the extension waited for approval, and the profile approved it. The profile-first order is not tested on a managed Mac yet.

Before the first fleet rollout, install the package on one test Mac with `sudo installer -pkg SafeRoom-<version>.pkg -target /`, with a user logged in. Then run `SafeRoom --status`. The post-install script submits the extension as the logged-in user. This step is not tested yet.

1. Edit `ProviderConfiguration` in the rendered `saferoom.mobileconfig` for your environment. The keys are in the next section. `make package` shows a warning while the profile holds the sample values (`example.com`, `REPLACE-WITH`, `yourcompany`).
2. In Jamf Pro, upload both profiles under Computers > Configuration Profiles. Scope them to a test group first.
3. Upload the package under Settings > Computer management > Packages.
4. Create a policy that installs the package, with the same scope. The package's post-install script runs `SafeRoom --activate`, which submits the extension.
5. Add the rendered `jamf-extension-attribute.sh` as an extension attribute. See "Status and Jamf inventory" below.
6. On a test Mac, run `sudo /Applications/SafeRoom.app/Contents/MacOS/SafeRoom --status`. The JSON shows the list and the policy in use.

To update SafeRoom, upload the new package and install it with a policy. macOS replaces the running extension. The cached list keeps blocking during the switch. If the SafeRoom window is open, the installer closes it before it replaces the app, and opens it again after.

To roll back, remove the profile from the scope. This deactivates the extension, and a restart of the Mac removes it. Then remove `/Applications/SafeRoom.app` with a script.

To change the policy, edit the profile in Jamf. The extension reads the policy at each start of the proxy, so the change takes effect at the next start. A restart of the Mac starts the proxy again.

## Keys

| Key | Type | Default | Meaning |
|---|---|---|---|
| `ListURL` | string | none | HTTPS URL of the blocklist. When set, this URL is the main source. |
| `ListPath` | string | `/Library/Application Support/SafeRoom/blocklist.txt` | Local blocklist. The path must be inside `/Library/Application Support/SafeRoom/`, which only root can write. Other paths are ignored. The file must be owned by root and must not be writable by group or others, or SafeRoom refuses it. The installer package creates the folder with the right owner. If `ListURL` is not set, SafeRoom reads this file. If the URL fails and no list is loaded yet, SafeRoom also reads it. |
| `ListSHA256URL` | string | none | URL of a file with the list's SHA-256 hash in hex. If set, SafeRoom downloads this file first at each check, and downloads the list only when the hash is not the hash of the list in use. If the hash does not match the download, SafeRoom rejects the download. |
| `Auth` | dictionary | none | How to authenticate to `ListURL`. See the next section. |
| `AllowList` | array of strings | empty | Domains that SafeRoom never blocks. The forms are the same as in the blocklist. |
| `NeverBlockHosts` | array of strings | empty | More domains that SafeRoom never blocks, added to the built-in set. Put your MDM server here. |
| `RefreshSeconds` | integer | 3600 | Time between checks. The minimum is 300. With `ListSHA256URL`, a check of an unchanged list downloads only the hash file, so 300 is a good value. |
| `MaxChangePercent` | integer | 0 | If the entry count of a new list changes by more than this percentage, SafeRoom rejects it. 0, the default, turns the rule off. Read the warning in the update section before you turn it on. |
| `MaxListMegabytes` | integer | 64 | SafeRoom rejects a download larger than this. |
| `AllowTopLevelBlocks` | boolean | false | Lets list rules like `*.zip` block a whole top-level domain. Off by default, so a bad feed cannot block `*.com`. |
| `EventURL` | string | none | HTTPS URL that receives block events as JSON POST requests. If it is not set, SafeRoom posts no events. See [Block events](#block-events). |
| `EventAuth` | dictionary | none | How to authenticate to `EventURL`. Same form as `Auth`, with its own token. |
| `EventIntervalSeconds` | integer | 10 | Time between event posts. The range is 1 to 3600. |
| `EventAllQueries` | boolean | false | Sends every answered lookup to `EventURL`, not only blocks. Needs `EventURL`. See [All lookups](#all-lookups). |
| `MonitorOnly` | boolean | false | Blocks nothing, and reports each lookup that SafeRoom would have blocked. See [Monitor mode](#monitor-mode). |
| `PermitOnly` | boolean | false | Answers NXDOMAIN for every name that is not on `PermitList`, `AllowList`, or the never-block set. Needs a `PermitList` with at least one usable entry. See [Permit-only mode](#permit-only-mode). |
| `PermitList` | array of strings | empty | With `PermitOnly`, the names that may resolve. The forms are the same as in the blocklist. The threat list still applies to these names. |
| `EventServerPins` | array of strings | none | Pins for the `EventURL` server's key. If set, SafeRoom accepts the server only if its key matches a pin. See [Server pins](#server-pins). |

`ListURL`, `ListSHA256URL`, and `EventURL` must use HTTPS. Plain HTTP works only for `localhost` and `127.0.0.1`, for tests.

SafeRoom never blocks the host of `ListURL`, so a feed that lists its own server cannot stop the fix from arriving. SafeRoom also never blocks the host of `EventURL`, so a feed cannot stop the events. This applies to that exact name only. If the list is on a shared host, the names under it stay blockable.

## Auth

| `Type` | Other keys | Result |
|---|---|---|
| `bearer` | `Token` | SafeRoom sends `Authorization: Bearer <Token>`. |
| `clientCertificate` | `IdentitySubjectContains`, `IdentityIssuerContains` | SafeRoom presents a TLS client certificate from the keychain. Both keys are optional text filters on the certificate. See [mtls-okta.md](mtls-okta.md). |

Any local user can read the token, because macOS stores the proxy configuration in a file that every user can read. Prefer `clientCertificate`. If you use a token, give it read access to the list and nothing else, and make it easy to revoke.

SafeRoom follows a redirect only to the same host over the same scheme. It never sends the token to another host.

SafeRoom sends the `EventAuth` token only to `EventURL`. Give it permission to add events and nothing else. Do not use the list token for events.

SafeRoom also sends the token with the hash file download if the hash file is on the same host and port as `ListURL`. With `ListSHA256URL` set and `RefreshSeconds` at 300, the token goes to the server every 5 minutes instead of once an hour. Server logs that record the `Authorization` header then hold more copies of it.

## Block events

If `EventURL` is set, SafeRoom sends each blocked query and each blocked answer to that URL. The event has the same data as the line in the `block` log category. With `MonitorOnly`, it sends the lookups that it would have blocked. With `PermitOnly`, it sends each name that is not on the permit list. With `EventAllQueries`, it also sends every other answered lookup.

SafeRoom collects the events in memory and sends them in batches, at most 500 in one request. A threat-list match (`blocked` or `wouldBlock`) does not wait. SafeRoom sends it within a quarter of a second, and it goes first in the request. Other events (`denied`, `wouldDeny`, and `allowed`) wait for the next post, every `EventIntervalSeconds`. If 500 events are waiting before the interval ends, SafeRoom sends them at once. The request is a `POST` with `Content-Type: application/json`. If `EventAuth` has the type `bearer`, the request carries `Authorization: Bearer <Token>`. The `clientCertificate` type also works, with the same keys as in `Auth`.

This is an example of a request body:

```json
{
  "device": {"hostname": "mac-0142", "serialNumber": "C02XYZ123ABC", "version": "0.1.4 (19)"},
  "sentAt": "2026-10-27T21:40:10Z",
  "dropped": 0,
  "events": [
    {"time": "2026-10-27T21:40:02Z", "kind": "query", "name": "bad.example", "type": 1,
     "rule": "bad.example", "app": "com.apple.Safari", "transport": "udp"},
    {"time": "2026-10-27T21:40:05Z", "kind": "answer", "name": "cdn.example", "alias": "bad.example",
     "rule": "bad.example", "app": "com.google.Chrome", "transport": "udp"},
    {"time": "2026-10-27T21:40:07Z", "kind": "answer", "name": "host.example", "address": "203.0.113.9",
     "app": "curl", "transport": "tcp"}
  ]
}
```

| Field | Meaning |
|---|---|
| `device.hostname` | The local host name of the Mac. |
| `device.serialNumber` | The hardware serial number, the same as in the MDM inventory. Missing if SafeRoom cannot read it. |
| `device.version` | The SafeRoom version and build. |
| `dropped` | The number of events that SafeRoom lost since the previous request, because too many events were waiting. |
| `action` | `blocked` if the threat list matched and SafeRoom answered NXDOMAIN. `wouldBlock` if the threat list matched and `MonitorOnly` let the lookup through. `denied` if the name is not on the permit list and SafeRoom answered NXDOMAIN. `wouldDeny` if the name is not on the permit list and `MonitorOnly` let the lookup through. `allowed` for a lookup that nothing matched, sent only with `EventAllQueries`. |
| `kind` | `query` if the query name is on the list, and for every `denied`, `wouldDeny`, and `allowed` event. `answer` if the upstream answer named a listed alias or address. |
| `name` | The name in the query. |
| `type` | The DNS record type of the query, as a number. Only for `query`. |
| `rule` | The list rule that matched. |
| `alias` | The listed CNAME or SVCB target in the answer. |
| `address` | The listed address in the answer. |
| `addresses` | `allowed` only: every A, AAAA, and SVCB hint address in the answer. Missing if the answer has none, for example an NXDOMAIN from the resolver. |
| `aliases` | `allowed` only: every CNAME and SVCB target in the answer. Missing if there are none. |
| `app` | The code signing identifier of the app that asked. |
| `transport` | `udp` or `tcp`. |

The server must reply with a status from 200 to 299. SafeRoom does not read the reply body. If a request fails, SafeRoom keeps the events and tries again after 1 minute, then 2, 4, 8, and so on, up to 10 minutes. Threat-list events also wait for these retries, so a server that is down does not get a request every second. Each wait is longer or shorter by up to a quarter, at random, so that a fleet of Macs does not retry at the same moment after an outage. SafeRoom never follows a redirect from `EventURL`.

SafeRoom keeps at most 10,000 events in memory. If more are waiting, for example while the server is down, SafeRoom drops the oldest tenth and counts them in `dropped`. It drops other events before threat-list events, so a flood of `allowed` events cannot push out a block. Events are not written to disk. When the proxy stops, for example for an upgrade, SafeRoom lets a request in progress finish, then makes one last request with the waiting events. Both together get at most 2 seconds. If that request fails, the events are lost.

### Monitor mode

With `MonitorOnly` set to `true`, SafeRoom blocks nothing. It checks each answer against the list, and it reports each lookup that it would have blocked: an event with `action` `wouldBlock`, and a `would block` line in the `block` log category. Use it to try a new list, or for a first rollout, before you turn blocking on.

- SafeRoom reports each such lookup once, when the answer comes back. A lookup with no answer, for example because the resolver timed out, is not reported.
- The allow list and the never-block set apply, as when SafeRoom blocks.
- SafeRoom does not learn names from listed addresses in monitor mode (docs/list-format.md). An AAAA lookup for a host listed only by its IPv4 address is therefore not reported.
- The window shows "Monitoring only". `SafeRoom --jamf` starts its line with `MONITOR` instead of `OK`, so a Mac that blocks nothing stays out of an "OK" smart group, and `SafeRoom --status` shows `policy.monitorOnly` and `counters.wouldBlock`.

`blocked` events and `block` log lines do not appear in monitor mode, so a SIEM rule that alerts on them stays quiet. Write a separate rule for `wouldBlock` if you want one.

### Permit-only mode

With `PermitOnly` set to `true`, SafeRoom answers NXDOMAIN for every name that is not permitted. The threat list stays in force. SafeRoom checks each query name in this order:

1. If the name is on `AllowList`, the never-block set, or is the host of `ListURL`, `ListSHA256URL`, or `EventURL`, SafeRoom lets it through. The threat list does not apply to it.
2. If the name is on the threat list, SafeRoom blocks it, and sends a `blocked` event at once. This also applies to a name on `PermitList`.
3. If the name is on `PermitList`, SafeRoom lets it through.
4. If not, SafeRoom answers NXDOMAIN, sends a `denied` event, and writes a `denied query` line in the `block` log category.

Only the query name must be on `PermitList`. SafeRoom checks the CNAME targets and addresses in the answer against the threat list, but not against `PermitList`. Most sites answer through a CDN name, for example `www.example.com` as an alias of `example.com.cdn.example.net`, and a check of the alias would break them.

Use `AllowList` for a name that the threat list matches by mistake. Use `PermitList` for every other name that the Macs need. If `PermitOnly` is `true` and `PermitList` has no usable entry, SafeRoom ignores `PermitOnly` and logs the reason, because a profile mistake must not cut every Mac off.

Permit-only mode works with no threat list loaded. In that case, `SafeRoom --jamf` reports `NO LIST`, and the window says that only names on the permit list resolve.

Names that a permit list often misses:

- Your internal domains, for example the Active Directory domain and its `_ldap._tcp` and `_kerberos._tcp` service records.
- Reverse lookups (`in-addr.arpa` and `ip6.arpa`). Most apps work without them, but logs and some tools are slower. Do not permit all of `arpa`, because a name under it can carry data out of the network.
- Certificate revocation servers of other certificate authorities, for example `ocsp.digicert.com`. macOS continues if they fail, but each check waits for the timeout.
- Printers, conferencing services, and the identity provider if it is not Okta.

To build the list, start in monitor mode. With `MonitorOnly` and `PermitOnly` both `true`, SafeRoom blocks nothing. It sends a `wouldDeny` event for each name that is not permitted, and a `wouldBlock` event for each threat-list match. Collect the `wouldDeny` names for a week, add the ones you need to `PermitList`, then set `MonitorOnly` to `false`.

The window shows "Permit only" in the policy section, and the count of denied lookups replaces the IP ranges count. `SafeRoom --jamf` adds "permit only (N names)" to its line. `SafeRoom --status` shows `policy.permitListCount` and `counters.notPermitted`.

### All lookups

With `EventAllQueries` set to `true`, SafeRoom sends every answered lookup to `EventURL`, from every app, as an event with `action` `allowed`. The event holds the name, the record type, the addresses and aliases in the answer, and the app that asked. Blocked lookups keep their own events, so each lookup appears once. A lookup with no answer is not sent.

This is many more events. A Mac in use makes several thousand lookups an hour. Size the server for that, and set `EventIntervalSeconds` to 60 or less, so that the 10,000-event buffer does not fill while the server is down. `events.dropped` in `SafeRoom --status` shows lost events.

The events are a full record of the names that each Mac looks up. Treat them as you treat browser history. Allowed lookups are not written to the unified log.

### Server pins

`EventServerPins` lets SafeRoom post to a server with a self-signed certificate, for example a load balancer inside your network. Each entry is the base64 SHA-256 of the server's public key. Get it from the server's certificate with this command:

```sh
openssl x509 -in server.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
```

If `EventServerPins` is set, these rules apply:

- The server's key must be EC P-256 and must match one entry. A pin replaces the system trust check. SafeRoom does not check the certificate's name or dates, so an expired certificate with the same key still works.
- The connection must use TLS 1.3.
- If no entry is usable, SafeRoom refuses every post. It never falls back to the system trust check.
- SafeRoom 0.1.7 or later is needed. In 0.1.6, a second trust check (App Transport Security) refused a self-signed server after the pin matched, and every post failed with URLError -1200.
- To change the server key without losing events, add the new pin before you change the key, and remove the old pin after.

If a post fails, `SafeRoom --status` shows the reason under `events.lastError`, for example "server pin mismatch". The `policy.eventServerPins` field shows how many pins are usable.

If `EventAuth` uses `clientCertificate`, SafeRoom skips certificates that are expired or not yet valid. If more than one certificate matches, it takes the one that expires last. This rule also applies to `Auth`. Before SafeRoom sends a certificate to `EventURL`, it makes a test signature with its key. If the key cannot sign, `events.lastError` starts with "the client certificate's key cannot sign" and gives the keychain error.

### Connections to the event server

SafeRoom keeps its TLS connection to `EventURL` open between posts, if the server allows it. The TLS handshake, the pin check, and the client certificate then happen once per connection, not once per post. SafeRoom opens a new connection after a failed post, every 10 minutes, and whenever the server closes the idle connection. A new client certificate or a new server key therefore takes effect within 10 minutes, with no restart. `events.connectionsOpened` in `SafeRoom --status` counts the new connections. If it is close to `events.posted`, the server closes each connection before the next post.

The server's idle timeout must be longer than `EventIntervalSeconds`, or every post opens a new connection. If the server closes the connection at the moment that SafeRoom sends a post, SafeRoom tries once more at once, on a new connection. In that case the server can receive the same batch twice.

### Event server on AWS API Gateway

These settings follow the AWS documentation as of November 2026. Check the current documentation before you set up the server.

- Use a Regional custom domain name with mutual TLS, and give it a truststore with the CA that issues the certificate in `EventAuth`. Turn off the default `execute-api` endpoint, because it does not ask for a client certificate. API Gateway does not check certificate revocation. To block one Mac, use a Lambda authorizer, or use short-lived certificates.
- Do not set `EventServerPins`. ACM makes a new key when it renews a certificate, and a pin then refuses every post. Pins are for a server with a certificate that you manage yourself.
- An HTTP API costs about a third as much per request as a REST API, and supports only TLS 1.2. A REST API can require TLS 1.3, and its idle connection timeout is 310 seconds. AWS documents no idle timeout for HTTP APIs, so read `events.connectionsOpened` after a day.
- AWS bills each post as one request. A batch of 500 events is about 150 to 250 KB, which is one billing unit of an HTTP API. The posting interval sets the cost: 2,700 Macs at 10 seconds make about 700 million requests a month, and at 60 seconds about 117 million. Blocks do not wait for the interval, so a longer interval delays only the other events.

A slow or failed event server never changes or delays a DNS answer. Event failures do not change the health state. `SafeRoom --status` shows them under `events`.

## How SafeRoom updates the list

1. At start, SafeRoom loads its compiled cache. Blocking starts within a few milliseconds.
2. If `ListSHA256URL` is set, SafeRoom downloads the hash file. If the hash is the hash of the list in use, the check ends here as a success, with no list download.
3. SafeRoom downloads `ListURL`. If a list is loaded and no hash file is set, the request carries `If-None-Match` and `If-Modified-Since`, and an unchanged list costs a `304` reply.
4. SafeRoom applies these rules to a new list, in this order: HTTP status 200, size limit, SHA-256 match, not empty, and the `MaxChangePercent` limit.
5. If the list passes, SafeRoom installs it and writes a new cache. If it fails, SafeRoom keeps the current list and logs the reason.
6. After a success, SafeRoom waits `RefreshSeconds`. After a failure, it retries after 1 minute, then 2, 4, 8, and so on, up to `RefreshSeconds`. Each retry wait is longer or shorter by up to a quarter, at random.

With `RefreshSeconds` at 300, `STALE` starts after 15 minutes with no successful check, for example on a Mac with no network.

A server can publish the hash file and the list a few minutes apart, for example because a CDN caches each file for 5 minutes. During that time the downloaded list does not match the new hash. SafeRoom rejects it, keeps the current list, reports `DEGRADED`, and tries again after 1 minute.

The percentage rule is off by default. If you turn it on, a rejection does not clear by itself. When the feed changes size on purpose, for example because a source was added, every Mac keeps the old list until you raise `MaxChangePercent` in the profile. The rule skips lists with fewer than 100 entries. It also skips the first download after a change of `ListURL`, because it compares a feed only with itself.

## Changing the policy

The extension reads the policy once, at the start of the proxy. If you change `ProviderConfiguration`, the new policy takes effect at the next start. A reinstall of the profile or a restart of the Mac starts the proxy again.

The extension receives the policy in the `options` of `startProxy`, under the key `VendorData`. In a system extension, `NEDNSProxyManager.shared()` does not return the payload's configuration.

## Status and Jamf inventory

The SafeRoom app binary has three command-line modes. They work from Terminal and from a root script, with no window.

| Command | Output |
|---|---|
| `SafeRoom --status` | The extension's status as JSON: the list, the last check, the policy, block counts, and event posts. |
| `SafeRoom --refresh` | Runs a check at once, then prints the status as JSON. The extension runs at most one manual check every 5 minutes. |
| `SafeRoom --jamf` | One line for a Jamf extension attribute. |

The binary is at `/Applications/SafeRoom.app/Contents/MacOS/SafeRoom`.

To report SafeRoom health in Jamf inventory, add the rendered copy of [`mdm/jamf-extension-attribute.sh`](../mdm/jamf-extension-attribute.sh) as an extension attribute with the data type String. The result starts with one of these states:

| State | Meaning |
|---|---|
| `OK` | A list is loaded, and the last check succeeded. With `PermitOnly`, the line also says "permit only (N names)". |
| `MONITOR` | As `OK`, but `MonitorOnly` is on: nothing is blocked. If the list also has a problem, the line starts with that state and then says "MONITOR ONLY". |
| `DEGRADED` | Recent checks failed. The list in use is not stale yet. With a hash file, a short `DEGRADED` period after a new list is published is normal. See [How SafeRoom updates the list](#how-saferoom-updates-the-list). |
| `STALE` | No check succeeded for three refresh intervals. |
| `NO LIST` | No list is loaded. Every query passes. With `PermitOnly`, only permitted names resolve. |
| `NOT RUNNING` | The extension or the proxy does not answer. |
| `TAMPERED` | The app at `/Applications/SafeRoom.app` is not signed by the SafeRoom developer. Its output is not trusted. |
| `NOT INSTALLED` | The app is not in `/Applications`. |

For example, a smart group with the criterion "SafeRoom health does not begin with OK" finds every Mac that needs attention.

The app and the extension talk over XPC. Each side reads the code signature of the other, and refuses the connection unless the team ID is the same. Other processes on the Mac cannot read the status or start a download.

## Log

Run this command to watch SafeRoom:

```sh
log stream --predicate 'subsystem == "com.oldsalt.saferoom"'
```

| Category | Content |
|---|---|
| `provider` | Start, stop, and the policy in use. Each policy value that SafeRoom ignores, with the reason. The token and the URLs of ignored values are never logged. |
| `list` | Downloads, rejections with the reason, and invalid lines. |
| `block` | Each blocked query or answer, with the rule and the app that asked. In monitor mode, each lookup that SafeRoom would have blocked, as a `would block` line. |
| `flow` | Connection errors. |
| `event` | Failed event posts, with the reason. |
