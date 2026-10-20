# Blocklist format

A SafeRoom blocklist is a plain text file in UTF-8. Each line holds one entry. The allowlist in the MDM policy uses the same domain forms.

## Domain entries

| Line | Blocks | Does not block |
|---|---|---|
| `evil.com` | `evil.com`, `a.evil.com`, `a.b.evil.com` | `notevil.com` |
| `=evil.com` | `evil.com` | `a.evil.com` |
| `*.evil.com` | `a.evil.com`, `a.b.evil.com` | `evil.com` |
| `.evil.com` | Same as `evil.com` | |
| `\|\|evil.com^` | Same as `evil.com` (Adblock syntax) | |
| `*.zip` | Every name in the `.zip` top-level domain | |

A bare name blocks the name and all names under it, because threat feeds expect that behavior.

SafeRoom changes each name to lowercase and removes a trailing dot. Names can contain the letters a to z, the digits 0 to 9, `-`, and `_`.

## Address entries

| Line | Blocks answers in |
|---|---|
| `198.51.100.0/24` | 198.51.100.0 to 198.51.100.255 |
| `203.0.113.9` | That one address (a /32) |
| `2001:db8::/32` | That IPv6 range |
| `::1` | That one IPv6 address (a /128) |

An address entry applies to DNS answers. SafeRoom reads the A records and the AAAA records in each answer. It also reads the `ipv4hint` and `ipv6hint` values in HTTPS and SVCB records, because browsers connect to those addresses. If one address is in a listed range, SafeRoom replaces the whole answer with NXDOMAIN.

An address entry does not block a direct connection to that address, because a direct connection does not use DNS.

## Aliases and the allowlist

SafeRoom also checks the targets of CNAME records and of HTTPS and SVCB records. If `innocent.org` is an alias for `cdn.evil.com`, and `evil.com` is on the list, the answer for `innocent.org` becomes NXDOMAIN.

An allowlist match always wins. If a queried name is on the allowlist or on the built-in never-block list, SafeRoom does not check its answer at all. Use the allowlist to fix a false positive, for example a CDN range in a feed that also serves a site you need.

If an entry has host bits set below the prefix, SafeRoom clears them. For example, `198.51.100.77/24` becomes `198.51.100.0/24`.

## Other accepted forms

Hosts-file lines are accepted. In `0.0.0.0 evil.com`, the address is ignored and the names after it become domain entries. One line can list several names. `localhost` and similar loopback names are ignored.

A URL is accepted, and only its host is kept. `https://evil.com/login` becomes `evil.com`.

Text after `#` is a comment. A line that starts with `!` is a comment. Blank lines are ignored.

## Rejected lines

SafeRoom skips each line it cannot read, counts it, and logs the first 50. One bad line never stops the rest of the list from loading.

These lines are rejected:

- A name with non-ASCII characters. Write an international name in punycode, for example `xn--80ak6aa92e.com`.
- A wildcard anywhere except as a leading `*.`, for example `evil.*` or `a.*.evil.com`.
- A single label without `*.`, for example `com`. To block a whole top-level domain, write `*.com`. This rule stops a stray line from blocking a whole TLD by accident.
- A label longer than 63 bytes, or a name longer than 253 bytes.
- A CIDR prefix that is too long, for example `/33` for IPv4.
- A two-field line whose first field is not an IP address.

## Example

```
# Feed: example-intel, 2026-10-19
evil.com
=login.evil-cdn.net
*.dyn-malware.org
0.0.0.0 phish.example.net
198.51.100.0/24
2001:db8:bad::/48
```
