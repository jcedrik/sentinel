# Benchmark results

`make bench` on the session machine (g++ 13, -O3, single thread, 32 MB random haystack over a 44-symbol alphabet with 2,000 planted matches). Naive = one `memmem` pass per pattern over the whole haystack; at 1,000 and 10,000 patterns it is timed on a 2 MB slice and scaled, otherwise the run takes an hour.

| Signatures | Engine | Build (ms) | Scan (ms) | Throughput (MB/s) | Matches | Table (MB) | Nodes |
|---:|---|---:|---:|---:|---:|---:|---:|
| 10 | aho-corasick | 0.2 | 119.1 | 268.6 | 1997 | 0.0 | 131 |
| 10 | naive-memmem | 0.0 | 52.1 | 614.3 | 1997 |  |  |
| 100 | aho-corasick | 2.8 | 124.7 | 256.6 | 1998 | 0.3 | 1505 |
| 100 | naive-memmem | 0.0 | 464.3 | 68.9 | 1998 |  |  |
| 1000 | aho-corasick | 17.0 | 237.3 | 134.9 | 1999 | 2.3 | 13835 |
| 1000 | naive-memmem | 0.0 | 4414.2 | 7.2 | 2016 |  |  |
| 10000 | aho-corasick | 249.7 | 591.3 | 54.1 | 2003 | 22.0 | 131094 |
| 10000 | naive-memmem | 0.0 | 42735.9 | 0.7 | 1872 |  |  |

![throughput](../docs/benchmark.png)

## Before and after the compressed table

First run, with the textbook 256-wide `int` row per node (1 KB per node):

| Signatures | MB/s | Table |
|---:|---:|---:|
| 10 | 193 | 0.1 MB |
| 100 | 177 | 1.5 MB |
| 1,000 | 87 | 14 MB |
| 10,000 | 28 | 131 MB |

After remapping bytes onto the 44 symbols the ruleset actually uses (`build()` in `aho_corasick.cpp`):

| Signatures | MB/s | Table | Speed-up |
|---:|---:|---:|---:|
| 10 | 269 | 0.02 MB | 1.4x |
| 100 | 257 | 0.3 MB | 1.5x |
| 1,000 | 135 | 2.3 MB | 1.6x |
| 10,000 | 54 | 22 MB | 1.9x |

## Reading the curve honestly

The textbook says Aho-Corasick is O(T + matches) regardless of the number of patterns, so the line should be flat. It is not: 269 MB/s at 10 signatures, 54 MB/s at 10,000. The per-byte work *is* constant (one table load), but the table grows with the ruleset and stops fitting in cache: 22 MB at 10,000 patterns against a few MB of L2. What you are looking at is memory latency, not algorithmic cost. The naive engine loses a factor of ten per decade because its cost really is O(N x T); the automaton loses a factor of two per decade because of cache misses. The crossover where the automaton wins is around 30 signatures; below that, a SIMD `memmem` over a handful of patterns is simply faster.

Next steps that would flatten the curve further: a double-array trie (smaller rows, better locality), `uint16_t` state ids for rulesets under 65k nodes, and ordering nodes by BFS depth so hot states share cache lines.
