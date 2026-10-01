# Raw session export

[Research files and tools](TOOLS.md) · [Original-file manifest](RESEARCH_FILES_MANIFEST.json)

[Open the raw ZIP](dsh-session-session-aa1e3da7-02f5-4131-ac2e-d9b84079a51d.zip) · [Integrity manifest](ARCHIVE_MANIFEST.json) · [Checksums](SHA256SUMS)

The [README](README.md) is an exact copy of the selected `SESSION_RECORD_2026-09-30.md`. The original session ZIP is preserved byte for byte.

The ZIP contains four JSONL event streams documenting the main session and three delegated research sessions. Each line is a JSON event. These records preserve messages, tool arguments and outputs, code edits, and device observations.

| Stream | Expanded bytes | Events |
|---|---:|---:|
| `session.v4.jsonl` | 75,921,317 | 11,101 |
| `subagents/e1d39dad-6787-49df-b104-54b305863001/session.v4.jsonl` | 867,070 | 152 |
| `subagents/eb025e1d-8f1d-4d81-a125-c01242a5d772/session.v4.jsonl` | 2,773,296 | 551 |
| `subagents/1950112f-1ffe-4691-a6fc-6c18ce1e9edd/session.v4.jsonl` | 241,256 | 69 |

Archive size: 17,647,101 bytes compressed, 79,802,939 bytes expanded. Total events: 11,873.

The manifest records hashes for the ZIP, README, and each stream, along with event counts. This makes it possible to identify the original files and check integrity later.

## GitHub metadata

Suggested repository name: `portal-adb-recovery-session-archive`.

Suggested description (also in [DESCRIPTION.txt](DESCRIPTION.txt)):

> Meta Portal 10-inch recovery research: V8 renderer read/write primitives, WebAssembly indirect-call control, native execution barriers, kernel/EDL findings, OTA extraction, and ADB/OOBE analysis.

Suggested topics: `meta-portal`, `android`, `v8`, `arm32`, `adb`, `firmware-research`, `session-archive`.
