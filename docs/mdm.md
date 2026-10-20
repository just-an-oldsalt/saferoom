# MDM policy

An MDM configures SafeRoom with the DNS Proxy payload (`com.apple.dnsProxy.managed`). The payload's `ProviderConfiguration` dictionary holds the SafeRoom policy. This page lists every key.

SafeRoom ignores keys that it does not know. If a value has the wrong type or an invalid form, SafeRoom uses the default value for that key. A typing error in a profile never stops the proxy.

## Keys

| Key | Type | Default | Meaning |
|---|---|---|---|
| `ListURL` | string | none | HTTPS URL of the blocklist. When set, this URL is the main source. |
| `ListPath` | string | `/Library/Application Support/SafeRoom/blocklist.txt` | Local blocklist. If `ListURL` is not set, SafeRoom reads this file. If the URL fails and no list is loaded yet, SafeRoom also reads it. |
| `ListSHA256URL` | string | none | URL of a file with the list's SHA-256 hash in hex. If the hash does not match the download, SafeRoom rejects the download. |
| `Auth` | dictionary | none | How to authenticate to `ListURL`. See the next section. |
| `AllowList` | array of strings | empty | Domains that SafeRoom never blocks. The forms are the same as in the blocklist. |
| `NeverBlockHosts` | array of strings | empty | More domains that SafeRoom never blocks, added to the built-in set. Put your MDM server here. |
| `RefreshSeconds` | integer | 3600 | Time between downloads. The minimum is 300. |
| `MaxChangePercent` | integer | 50 | If the entry count of a new list changes by more than this percentage, SafeRoom rejects it. 0 turns the rule off. |
| `MaxListMegabytes` | integer | 64 | SafeRoom rejects a download larger than this. |

`ListURL` and `ListSHA256URL` must use HTTPS. Plain HTTP works only for `localhost` and `127.0.0.1`, for tests.

SafeRoom adds the host of `ListURL` to the never-block set. A feed that lists its own server can then never stop the fix from arriving.

## Auth

| `Type` | Other keys | Result |
|---|---|---|
| `bearer` | `Token` | SafeRoom sends `Authorization: Bearer <Token>`. |
| `clientCertificate` | `IdentitySubjectContains`, `IdentityIssuerContains` | SafeRoom presents a TLS client certificate from the keychain. Both keys are optional text filters on the certificate. See [mtls-okta.md](mtls-okta.md). |

An administrator on a managed Mac can read the profile, and so can read a bearer token in it. Give the token read access to the list and nothing else.

SafeRoom follows a redirect only to the same host over the same scheme. It never sends the token to another host.

## How SafeRoom updates the list

1. At start, SafeRoom loads its compiled cache. Blocking starts within a few milliseconds.
2. SafeRoom downloads `ListURL`. If a list is loaded, the request carries `If-None-Match` and `If-Modified-Since`, and an unchanged list costs a `304` reply.
3. SafeRoom applies these rules to a new list, in this order: HTTP status 200, size limit, SHA-256 match, not empty, and the `MaxChangePercent` limit.
4. If the list passes, SafeRoom installs it and writes a new cache. If it fails, SafeRoom keeps the current list and logs the reason.
5. After a success, SafeRoom waits `RefreshSeconds`. After a failure, it retries after 1 minute, then 2, 4, 8, and so on, up to `RefreshSeconds`.

The percentage rule skips lists with fewer than 100 entries. To accept an intended large change, raise `MaxChangePercent` for one refresh, then set it back.

## Changing the policy

The extension reads the policy once, at the start of the proxy. If you change `ProviderConfiguration`, the new policy takes effect at the next start. A reinstall of the profile or a restart of the Mac starts the proxy again.

The extension receives the policy in the `options` of `startProxy`, under the key `VendorData`. In a system extension, `NEDNSProxyManager.shared()` does not return the payload's configuration.

## Log

Run this command to watch SafeRoom:

```sh
log stream --predicate 'subsystem == "com.oldsalt.saferoom"'
```

| Category | Content |
|---|---|
| `provider` | Start, stop, and the policy in use. The token is never logged. |
| `list` | Downloads, rejections with the reason, and invalid lines. |
| `block` | Each blocked query or answer, with the rule and the app that asked. |
| `flow` | Connection errors. |
