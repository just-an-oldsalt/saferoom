# Performance and limits

This page gives measured numbers for SafeRoom. It covers list size limits, memory use, update cost, and the time that SafeRoom adds to a DNS lookup.

All numbers come from a Mac mini with an Apple M4 chip and 16 GB of memory, macOS 27.0.1, SafeRoom 0.1.2 (build 16), on 2026-10-20. Run `make bench` to measure the list engine on your own hardware.

## Summary

| Question | Answer |
|---|---|
| Time added to a DNS lookup | Nothing measurable on a client socket that is already open. About 1.5 ms at the median when the client opens a new socket for the lookup. |
| Memory of the running extension | 18.6 MB with a list of 235,000 domains and 1,700 address ranges. |
| Memory per list entry | About 9 bytes. |
| Comfortable list size | Up to about 3 million domains. |
| Largest list tested | 10 million domains. It works, but each update needs 44 seconds and over 1 GB of memory while it compiles. |
| Default size limit | 64 MB of list text (`MaxListMegabytes`), which is about 3.5 million domains. |
| Update download (235,000 domains) | 4.7 MB of text, 1.7 MB on the wire with gzip. An unchanged list costs a 0-byte `304` reply. |
| Update compile time | About 4.4 seconds per million entries. The old list keeps blocking during the compile. |
| Start-up | The cached list loads in about 1 ms per 250,000 entries, before the first query. |

## Time added to each lookup

These timings are for 500 queries of each kind to the router, which was one Wi-Fi hop away, with a ping time of 2.4 ms on average. For the first table, SafeRoom was turned off in System Settings.

| Query | p50 | p95 | p99 |
|---|---|---|---|
| UDP, SafeRoom off, new socket per query (`github.com`) | 2.29 ms | 5.54 ms | 11.64 ms |
| UDP, SafeRoom on, one socket for all queries | 2.29 ms | 5.08 ms | 7.93 ms |
| UDP, SafeRoom on, new socket per query | 3.75 ms | 5.92 ms | 11.58 ms |
| UDP, SafeRoom on, blocked name, one socket | 0.07 ms | 0.13 ms | 0.17 ms |
| TCP, SafeRoom off (`github.com`) | 4.44 ms | 6.39 ms | 9.24 ms |
| TCP, SafeRoom on | 8.23 ms | 11.35 ms | 35.52 ms |

On a client socket that is already open, SafeRoom adds no measurable time: the median is 2.29 ms with SafeRoom on and with it off. The list check takes less than 1 microsecond.

The cost is in connection setup. SafeRoom handles each client socket as one flow. For each new flow, it opens its own connection to the resolver, and that takes about 1.5 ms. An app that opens a new socket for each lookup pays this each time. An app that reuses a socket pays it once.

A blocked name never reaches the network. SafeRoom answers in 0.07 ms at the median.

TCP costs more, because SafeRoom opens a second TCP connection to the resolver for each client connection. Clients use TCP only for large answers, so this case is rare.

## List size

The benchmark generates domains with 2 to 4 labels and an average length of about 20 characters, the same shape as real feeds. Half of the lookups are subdomains of listed names, and half are not listed.

| Domains | List text | Compile time | Peak memory while compiling | List in memory | Cache load | Lookup |
|---|---|---|---|---|---|---|
| 250,000 | 4.4 MB | 1.1 s | 46 MB | 2.2 MB | 0.9 ms | 215 ns |
| 1,000,000 | 17.4 MB | 4.3 s | 132 MB | 8.6 MB | 3.3 ms | 257 ns |
| 3,000,000 | 52.3 MB | 13.0 s | 375 MB | 25.8 MB | 9.6 ms | 368 ns |
| 5,000,000 | 87.1 MB | 21.9 s | 608 MB | 42.9 MB | 16.0 ms | 474 ns |
| 10,000,000 | 174.2 MB | 44.4 s | 1,169 MB | 85.8 MB | 31.8 ms | 634 ns |

Address ranges cost even less:

| Domains and ranges | Compile time | List in memory | Address lookup |
|---|---|---|---|
| 250,000 and 1,700 | 1.1 s | 2.2 MB | 14 ns |
| 250,000 and 100,000 | 1.2 s | 2.9 MB | 34 ns |
| 250,000 and 1,000,000 | 2.3 s | 6.6 MB | 46 ns |

The peak memory in these tables includes the benchmark's own copy of the generated list, so the extension's peak is somewhat lower. After a compile, the extension releases the parse data and keeps only the compiled list.

Lookups slow down a little as the list grows, because a larger table fits less well in the processor's cache. Even at 10 million domains, a lookup takes less than 1 microsecond.

## Where the limits are

Nothing breaks suddenly as a list grows. These are the limits that apply first:

1. **`MaxListMegabytes`, default 64 MB.** A larger download is rejected. At about 18 bytes per line, that is about 3.5 million domains. The policy can raise it to 1,024 MB.
2. **Compile time and memory.** Both grow in a straight line with the list. Above about 3 million domains, each update takes more than 13 seconds and several hundred MB of memory for that time. The old list keeps blocking during the compile, so this costs resources, not protection. macOS documents no memory limit for system extensions.
3. **Lines longer than 4,096 bytes are skipped.** No valid entry is near this length.
4. **cookbook only: 25 MiB per file.** Cloudflare serves static files up to 25 MiB, which limits the cookbook list to about 1.3 million domains. This limit does not apply to a list on your own server.

The cache file format allows up to 4 billion entries, so it is never the limit.

## Update cost

For each refresh, SafeRoom sends a conditional request. If the list did not change, the server answers `304` with no body, and nothing else happens. If the downloaded list has the same SHA-256 as the list in use, SafeRoom also skips the compile.

When the list changed, SafeRoom downloads it, compiles it, swaps it in, and writes a new cache file. For the 235,000-domain cookbook list, that is 1.7 MB on the wire and about 1 second of compile time on the test Mac.

## Other fixed limits

| Limit | Value | Why |
|---|---|---|
| Upstream connections per UDP client socket | 8 | A socket normally talks to one or two resolvers. The cap protects the extension's file descriptors. |
| Names remembered by learned blocks | 10,000 for 5 minutes | Bounds memory under a flood of distinct names. |
| Manual refreshes | One every 5 minutes | Any user can ask for a refresh. |
| Shortest refresh interval | 5 minutes | Protects the list server. |
