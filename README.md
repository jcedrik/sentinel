# sentinel

A multi-signature detection engine written in C++. It scans input (log lines,
reassembled payloads) against a ruleset of byte signatures and reports matches
with severity and category, in a single pass over each record regardless of how
many rules are loaded.

I built this to understand how a real IDS does pattern matching under the hood,
instead of treating it as a black box. The core is an Aho-Corasick automaton I
implemented from scratch.

## Why Aho-Corasick

A detection engine tests many signatures against the same bytes. The naive
approach runs one substring search per rule: with N rules over text of length T
that is O(N x T). Aho-Corasick compiles all the patterns into a single finite
automaton and finds every occurrence of every pattern in one pass, in
O(T + matches) after an O(total pattern length) build.

Concretely: loading 10 rules or 10,000 rules costs the same per byte scanned.
The work moves to build time, where the automaton's failure links are computed
once.

## Build

```bash
make          # builds the sentinel binary
make test     # builds and runs the test suites
make run      # scans the bundled sample with the default ruleset
```

Requires a C++17 compiler. No external dependencies.

## Usage

```bash
sentinel --rules <file> --input <file> [--json]
```

Scan the bundled sample:

```bash
./sentinel --rules signatures/default.rules --input samples/traffic.log
```

Exit codes: `0` no alerts, `1` alerts found, `2` error.

## Rule format

One rule per line, five semicolon-separated fields:

```
sid; severity; category; name; pattern
```

The pattern is matched as raw bytes. Non-printable bytes use Snort-style `|hex|`
escapes, so a NOP sled is `|90 90 90 90|` and a CRLF is `|0d 0a|`. Lines starting
with `#` are comments.

## License

MIT
