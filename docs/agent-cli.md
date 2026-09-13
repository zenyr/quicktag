# QuickTag agent CLI

Development branch: `agent-cli` in <https://github.com/zenyr/quicktag>.
Based on upstream `bdad2e92442439bb0f71c67aca608b7ca0a8c74c` (inspected 2026-09-13).
The upstream [local API proposal](https://github.com/v4nguard/quicktag/issues/24)
also identifies reference and string queries as integration targets.
The existing desktop application remains available. `quicktag-cli` uses the same
package reader, class tables, string decoder and scanner.

## Build and first queries

Use Windows or Linux and a recent Rust toolchain (validated with Rust 1.91).
`tiger-pkg` 0.20.1 explicitly does not compile on macOS because its Oodle loader
does not support macOS. Run the CLI on the machine containing the packages and
send requests through SSH. The CLI does not link the desktop renderer/audio player.
Oodle runtime libraries must be supplied for the host OS when reading compressed
packages. Windows package initialization also checks the game's `bin/x64` folder.
No game data or Oodle binaries are included in this fork.

```sh
cargo build --locked --release -p quicktag-cli
cargo test --locked -p quicktag-cli -p quicktag-scanner

# Replace both the path and game version with the actual dataset.
quicktag-cli --packages /data/d2/packages -v d2_sk info
quicktag-cli --packages /data/d2/packages -v d2_sk --cache /data/cache/sk.cache index
quicktag-cli --packages /data/d2/packages -v d2_sk --cache /data/cache/sk.cache strings "bray" --limit 10
quicktag-cli --packages /data/d2/packages -v d2_sk named "bray"
quicktag-cli --packages /data/d2/packages -v d2_sk tags --class 0x80800065 --limit 10
```

Run `--help` to see supported game versions. Always supply the actual version;
installation paths and game versions are never auto-selected. Use the same
working directory for index/query commands if using a custom `signatures.csv`.
Cache parent directories must already exist. Do not index concurrently into the
same cache path.

`index` loads or builds the scan cache. Other queries never start a full tag scan
implicitly. The underlying package manager may still build its own package-header
lookup cache at startup. English localized string search lazily builds the
localized string map once per session.

Each CLI cache has a `.dataset.json` sidecar binding it to its canonical package
path, game version, package filenames/sizes/modification times, signatures and local wordlist metadata.
A changed dataset is rejected; use another cache path or `index --rebuild`.
An existing GUI cache without this identity sidecar also requires `index --rebuild`.
The binary cache format is unchanged and remains readable by the desktop app.
File metadata is a practical invalidation check, not a cryptographic content hash.
Restart a persistent session after modifying game packages or signatures.

## Investigation workflow

1. `strings QUERY` finds raw strings with their containing tag and string index.
   `strings QUERY --source localized` finds English localized strings and hashes.
2. `string-refs 0xHASH` finds tags/offsets containing a localized string hash.
3. `tag TAG` returns the tag header, class name and size. Supplying `--cache` also
   returns scan counts. `matches TAG` pages through string hashes, signatures,
   wordlist hashes and raw strings.
4. `refs TAG --direction incoming` finds referring tags; `--direction outgoing`
   follows direct outgoing references. Rows preserve each occurrence's byte offset,
   source tag, target tag and detection basis. Header references have a null offset.
5. `bytes TAG --offset 0x120 --length 64` returns only the requested hex range.
   `export TAG --output FILE` saves the original decompressed payload and refuses
   to overwrite an existing file. Exported texture/audio payloads are not PNG/WAV.

**Hash notation:** tag arguments use exactly eight hex digits in QuickTag's GUI
byte order. For example, displayed `00008080` represents integer `0x80800000`.
Class IDs, string hashes and the `hash64` field are hexadecimal integers prefixed
with `0x`. Never interchange these representations without converting byte order.
A scanner hit is evidence of a matching value, not proof of a semantic relationship.
Unresolved 64-bit references have `target: null` and retain their integer `hash64`.

## Bounded output and persistent JSONL

Successful output has `{"schema_version":1,"ok":true,"data":...}`; operational
errors have `{"schema_version":1,"ok":false,"error":"..."}`. One-shot operational
errors exit with status 1. Argument errors/help use normal clap behavior.
Diagnostics go to stderr. Set `RUST_LOG=info` to watch indexing progress.

Lists default to 20 rows and allow 1–200 via `--limit`. `--offset` selects a page.
`total` and `next_offset` describe the result set; null means no more pages.
Ordering is deterministic within the same dataset/session. Each string preview
is limited to 240 Unicode characters with an explicit `text_truncated` flag.
Use original payload export for full raw content. Hex reads are limited to 4096
bytes. These bounds control response size; they are not an exact tokenizer budget.
Tag listings and string searches serialize only the requested page. Searches still
scan the in-memory index to count all matches; some other query types collect
matching rows before pagination. Large caches still consume substantial RAM.

```sh
quicktag-cli --packages /data/d2/packages -v d2_sk --cache /data/cache/sk.cache serve
```

Send one JSON object per line, without Markdown fences:

```jsonl
{"op":"info"}
{"op":"strings","query":"bray","source":"raw","limit":5}
{"op":"string_refs","hash":"0x12345678","limit":10}
{"op":"tag","hash":"00008080"}
{"op":"refs","hash":"00008080","direction":"incoming","limit":10}
{"op":"bytes","hash":"00008080","offset":288,"length":64}
```

The example hashes are placeholders, not claims that the dataset contains them.
JSON operation names use underscores where CLI names use hyphens. JSON byte
offsets are numbers. Responses are ordered one-to-one with requests; the protocol
is sequential and has no request IDs. A malformed/oversized request produces one
error response and the next request is still accepted. Lines over 64 KiB are
consumed without retaining the excess. EOF closes the session. Each process is
bound to one package dataset; its scanner/string caches stay loaded between
requests. `serve` cannot be nested. An MCP adapter can wrap this protocol later.

## Desktop feature coverage

| Desktop capability | CLI coverage in this iteration |
| --- | --- |
| Package list and tag headers | `packages`, `tags`, `tag` (class filter, sizes, names) |
| Named tags | `named` substring search |
| Raw/localized string search | `strings`, `string-refs`, `matches`; English localized map |
| Forward/reverse tag references | `refs`; 32-bit and resolved 64-bit, direct edges |
| Scan signatures and wordlist hashes | `matches`; custom signatures use upstream `signatures.csv` |
| Hex inspection and binary extraction | Bounded `bytes`, lossless payload `export` |
| Scan cache and progress | Explicit `index`, upstream progress via stderr logs |
| Recursive traversal | Compose direct `refs` queries; bounded graph traversal not yet implemented |
| Typed field/array interpretation | Class labels available; desktop's full field rendering not yet exposed |
| Texture preview/conversion | Original payload export only; decoded image export pending |
| Audio playback, banks and event browsing | Original payload export only; audio/event decoding pending |
| Shader decompilation | Pending |
| Space usage reports | Per-tag sizes; aggregation pending |
| External standalone-file viewer | Pending; commands currently use package datasets |
| Other-language string dumps | Pending; matches the upstream search map's English-only scope |

The first delivery targets text investigation and reference discovery. Full GUI
feature parity is not claimed. Follow-up priorities should be selected using real
Sunrise investigations: structured tag fields/arrays, bounded graph traversal,
then decoded texture/audio artifacts. Keep reusable decoding in library crates
so the GUI and CLI share behavior.

## Validation status

Synthetic tests exercise hash byte order, pagination, byte bounds, Unicode
clipping, request parsing/recovery, dataset invalidation, future-cache errors, and
equivalence of merged blocked-range lookup to the original scanner membership test.
Actual package queries and GUI/CLI result comparison require the user's dataset;
record the tested game build and examples before claiming data-level parity.

A repeatable data-backed smoke runner is provided at
`scripts/validate-agent-cli.py`. After indexing, pass the full local or SSH `serve`
command after `--`. It checks pagination, raw/localized search, string references,
reference bytes and reverse lookup, and session recovery after an invalid request.
Only request timings/counts are printed; it does not export game payloads.
