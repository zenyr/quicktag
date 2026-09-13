//! Bounded, machine-readable access to QuickTag's package and scan data.
use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand, ValueEnum};
use quicktag_scanner::{TagCache, cache::CacheLoadResult};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::OpenOptions,
    io::{self, BufRead, Write},
    path::PathBuf,
    sync::Arc,
};
use tiger_pkg::{GameVersion, PackageManager, TagHash, package_manager};

#[derive(Parser)]
#[command(
    version,
    about = "Headless QuickTag queries. JSON on stdout, diagnostics on stderr."
)]
struct Args {
    /// Explicit package directory; never autodetect a different game installation.
    #[arg(long)]
    packages: PathBuf,
    #[arg(short = 'v', long, value_enum)]
    game_version: GameVersion,
    /// Cache path. Run `index` first for queries requiring scanned data.
    #[arg(long)]
    cache: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Debug, Subcommand, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    /// Build/reuse an upstream-compatible scan cache. This is the only command that scans all packages.
    Index,
    /// Show the active dataset and hash notation.
    Info,
    /// Search named tag entries from package headers.
    Named {
        query: String,
        #[command(flatten)]
        #[serde(flatten)]
        page: Page,
    },
    /// Find tags containing a localized string hash (hex integer).
    StringRefs {
        hash: String,
        #[command(flatten)]
        #[serde(flatten)]
        page: Page,
    },
    /// List package metadata.
    Packages {
        #[command(flatten)]
        #[serde(flatten)]
        page: Page,
    },
    /// List/filter tag headers without reading tag payloads.
    Tags {
        /// Numeric class/reference ID, hexadecimal (0x optional).
        #[arg(long)]
        class: Option<String>,
        #[command(flatten)]
        #[serde(flatten)]
        page: Page,
    },
    /// Header and counts for one tag. Hashes use QuickTag's displayed byte order.
    Tag { hash: String },
    /// Direct incoming/outgoing references, with scan offsets where available.
    Refs {
        hash: String,
        #[arg(long, value_enum, default_value = "outgoing")]
        #[serde(default)]
        direction: Direction,
        #[command(flatten)]
        #[serde(flatten)]
        page: Page,
    },
    /// Search raw or English localized strings, returning one string per row.
    Strings {
        query: String,
        #[arg(long, value_enum, default_value = "raw")]
        #[serde(default)]
        source: StringSource,
        #[command(flatten)]
        #[serde(flatten)]
        page: Page,
    },
    /// Inspect scanned strings, wordlist hashes and signatures in one tag.
    Matches {
        hash: String,
        #[command(flatten)]
        #[serde(flatten)]
        page: Page,
    },
    /// Read at most 4096 bytes, returned as hex. Offset accepts decimal or 0x notation.
    Bytes {
        hash: String,
        #[arg(long, default_value = "0", value_parser = parse_usize)]
        #[serde(default)]
        offset: usize,
        #[arg(long, default_value = "64")]
        #[serde(default = "default_length")]
        length: usize,
    },
    /// Export the original decompressed tag payload, without overwriting an existing file.
    Export {
        hash: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Persistent JSONL queries over stdin/stdout. One command object per line.
    Serve,
}
fn default_length() -> usize {
    64
}
#[derive(Clone, Copy, Debug, Default, ValueEnum, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Direction {
    Incoming,
    #[default]
    Outgoing,
}
#[derive(Clone, Copy, Debug, Default, ValueEnum, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StringSource {
    #[default]
    Raw,
    Localized,
}
#[derive(Clone, Copy, Debug, clap::Args, Deserialize)]
struct Page {
    #[arg(long, default_value = "20")]
    #[serde(default = "default_limit")]
    limit: usize,
    #[arg(long, default_value = "0")]
    #[serde(default)]
    offset: usize,
}
fn default_limit() -> usize {
    20
}
impl Page {
    fn apply(self, rows: Vec<Value>) -> Result<Value> {
        ensure!(
            (1..=200).contains(&self.limit),
            "limit must be between 1 and 200"
        );
        let total = rows.len();
        let items: Vec<_> = rows
            .into_iter()
            .skip(self.offset)
            .take(self.limit)
            .collect();
        let end = self.offset.saturating_add(items.len());
        Ok(
            json!({"items": items, "total": total, "next_offset": if end < total {Some(end)} else {None}}),
        )
    }
}
fn parse_usize(s: &str) -> Result<usize, String> {
    if let Some(s) = s.strip_prefix("0x") {
        usize::from_str_radix(s, 16)
    } else {
        s.parse()
    }
    .map_err(|e| e.to_string())
}
fn hex32(s: &str) -> Result<u32> {
    Ok(u32::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16)
        .context("expected hexadecimal u32")?)
}
// QuickTag displays a TagHash as the little-endian bytes, not its integer value.
fn parse_tag(s: &str) -> Result<TagHash> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    ensure!(
        s.len() == 8,
        "tag hash must contain exactly 8 hex digits in QuickTag display order"
    );
    Ok(TagHash(hex32(s)?.swap_bytes()))
}
fn tag_name(t: TagHash) -> String {
    format!("{:08X}", t.0.swap_bytes())
}
fn clipped(s: &str) -> (String, bool) {
    (s.chars().take(240).collect(), s.chars().count() > 240)
}

struct Session {
    cache_path: Option<PathBuf>,
    cache: Option<TagCache>,
    strings: Option<quicktag_strings::localized::StringCache>,
}
impl Session {
    fn cache(&mut self) -> Result<&TagCache> {
        if self.cache.is_none() {
            let path = self
                .cache_path
                .as_ref()
                .context("this query requires --cache; build it with index first")?;
            self.cache = Some(match TagCache::load(path)? {
                CacheLoadResult::Loaded(cache) => cache,
                CacheLoadResult::Rebuild => {
                    bail!("cache missing, stale or invalid; run index explicitly")
                }
            });
        }
        Ok(self.cache.as_ref().unwrap())
    }
    fn query(&mut self, command: Command) -> Result<Value> {
        let pm = package_manager();
        match command {
            Command::Index => {
                let path = self.cache_path.as_ref().context("index requires --cache")?;
                let cache = quicktag_scanner::load_tag_cache_at(path)?;
                let result = json!({"cache": path, "tags": cache.hashes.len(), "failed_tags": cache.hashes.values().filter(|s| !s.successful).count(), "cache_version": cache.version});
                self.cache = Some(cache);
                Ok(result)
            }
            Command::Info => Ok(
                json!({"packages":pm.package_dir,"game_version":format!("{:?}",pm.version),"cache_key":pm.cache_key(),"tag_hash_format":"8 hex digits in QuickTag display (little-endian byte) order","numeric_hash_format":"0x-prefixed hex integers","cache":self.cache_path}),
            ),
            Command::Named { query, page } => {
                let needle = query.to_lowercase();
                let mut rows: Vec<_> = pm
                    .lookup
                    .named_tags
                    .iter()
                    .filter(|n| n.name.to_lowercase().contains(&needle))
                    .map(|n| {
                        let (name, truncated) = clipped(&n.name);
                        json!({"tag":tag_name(n.hash),"name":name,"text_truncated":truncated})
                    })
                    .collect();
                rows.sort_by_cached_key(|r| r.to_string());
                page.apply(rows)
            }
            Command::StringRefs { hash, page } => {
                let hash = hex32(&hash)?;
                let mut tags: Vec<_> = self.cache()?.hashes.iter().collect();
                tags.sort_by_key(|(h, _)| h.0);
                let rows = tags.into_iter().flat_map(|(tag,scan)| scan.string_hashes.iter().filter(move |x|x.hash == hash).map(move |x|json!({"tag":tag_name(*tag),"offset":x.offset,"basis":"hash_match"}))).collect();
                page.apply(rows)
            }
            Command::Packages { page } => {
                let mut rows: Vec<_> = pm
                    .package_paths
                    .iter()
                    .map(|(id, p)| (*id, json!({"package_id": id, "path": p.path})))
                    .collect();
                rows.sort_by_key(|r| r.0);
                page.apply(rows.into_iter().map(|r| r.1).collect())
            }
            Command::Tags { class, page } => {
                let filter = class.as_deref().map(hex32).transpose()?;
                let mut hashes = vec![];
                for (pkg, entries) in &pm.lookup.tag32_entries_by_pkg {
                    for (i, e) in entries.iter().enumerate() {
                        if filter.is_none_or(|c| e.reference == c) {
                            hashes.push(TagHash::new(*pkg, i as u16));
                        }
                    }
                }
                hashes.sort_by_key(|h| h.0);
                page.apply(hashes.into_iter().map(header).collect())
            }
            Command::Tag { hash } => {
                let tag = parse_tag(&hash)?;
                ensure!(pm.get_entry(tag).is_some(), "tag not found");
                let mut out = header(tag);
                if self.cache_path.is_some() {
                    out["scan"] = match self.cache()?.hashes.get(&tag) {
                        Some(s) => {
                            json!({"successful": s.successful, "outgoing32": s.file_hashes.len(), "outgoing64": s.file_hashes64.len(), "incoming": s.references.len(), "raw_strings": s.raw_strings.len(), "string_hashes": s.string_hashes.len(), "signatures": s.signatures.len(), "secondary_class": s.secondary_class.map(|c|format!("0x{c:08X}"))})
                        }
                        None => Value::Null,
                    };
                }
                Ok(out)
            }
            Command::Refs {
                hash,
                direction,
                page,
            } => {
                let tag = parse_tag(&hash)?;
                let cache = self.cache()?;
                let scan = cache.hashes.get(&tag).context("tag has no scan data")?;
                let mut rows = vec![];
                match direction {
                    Direction::Outgoing => append_edges(&mut rows, tag, scan, None),
                    Direction::Incoming => {
                        let mut sources = scan.references.clone();
                        sources.sort_by_key(|h| h.0);
                        sources.dedup();
                        for source in sources {
                            if let Some(s) = cache.hashes.get(&source) {
                                append_edges(&mut rows, source, s, Some(tag));
                            }
                        }
                    }
                }
                page.apply(rows)
            }
            Command::Strings {
                query,
                source,
                page,
            } => {
                let needle = query.to_lowercase();
                let mut rows = vec![];
                match source {
                    StringSource::Raw => {
                        let mut tags: Vec<_> = self.cache()?.hashes.iter().collect();
                        tags.sort_by_key(|(h, _)| h.0);
                        for (tag, scan) in tags {
                            for (index, text) in scan.raw_strings.iter().enumerate() {
                                if text.to_lowercase().contains(&needle) {
                                    let (text, truncated) = clipped(text);
                                    rows.push(json!({"tag": tag_name(*tag), "index": index, "text": text, "text_truncated": truncated}));
                                }
                            }
                        }
                    }
                    StringSource::Localized => {
                        if self.strings.is_none() {
                            self.strings = Some(quicktag_strings::localized::create_stringmap()?);
                        }
                        let mut strings: Vec<_> = self.strings.as_ref().unwrap().iter().collect();
                        strings.sort_by_key(|(h, _)| **h);
                        for (hash, texts) in strings {
                            for text in texts {
                                if text.to_lowercase().contains(&needle) {
                                    let (text, truncated) = clipped(text);
                                    rows.push(json!({"string_hash": format!("0x{hash:08X}"), "text": text, "text_truncated": truncated}));
                                }
                            }
                        }
                    }
                }
                page.apply(rows)
            }
            Command::Matches { hash, page } => {
                let tag = parse_tag(&hash)?;
                let scan = self
                    .cache()?
                    .hashes
                    .get(&tag)
                    .context("tag has no scan data")?;
                let mut rows = vec![];
                for x in &scan.string_hashes {
                    rows.push(json!({"kind":"localized_hash", "offset": x.offset, "hash": format!("0x{:08X}", x.hash), "basis":"hash_match"}));
                }
                for x in &scan.wordlist_hashes {
                    rows.push(json!({"kind":"wordlist_hash", "offset": x.offset, "hash": format!("0x{:08X}", x.hash), "basis":"hash_match"}));
                }
                for x in &scan.signatures {
                    rows.push(json!({"kind":"signature", "offset": x.offset, "signature": format!("{:?}", x.hash), "basis":"value_match"}));
                }
                for (index, text) in scan.raw_strings.iter().enumerate() {
                    let (text, truncated) = clipped(text);
                    rows.push(json!({"kind":"raw_string", "index":index, "text":text, "text_truncated":truncated}));
                }
                page.apply(rows)
            }
            Command::Bytes {
                hash,
                offset,
                length,
            } => {
                ensure!(
                    (1..=4096).contains(&length),
                    "length must be between 1 and 4096"
                );
                let tag = parse_tag(&hash)?;
                let data = pm.read_tag(tag)?;
                let bytes = byte_range(&data, offset, length)?;
                let hex: String = bytes.iter().map(|b| format!("{b:02X}")).collect();
                Ok(
                    json!({"tag":tag_name(tag), "offset":offset, "length":bytes.len(), "size":data.len(), "hex":hex}),
                )
            }
            Command::Export { hash, output } => {
                let tag = parse_tag(&hash)?;
                let data = pm.read_tag(tag)?;
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&output)?;
                file.write_all(&data)?;
                Ok(
                    json!({"tag":tag_name(tag), "output":std::fs::canonicalize(output)?, "bytes":data.len()}),
                )
            }
            Command::Serve => bail!("serve cannot be nested"),
        }
    }
}
fn byte_range(data: &[u8], offset: usize, length: usize) -> Result<&[u8]> {
    ensure!(offset <= data.len(), "offset exceeds tag size");
    Ok(&data[offset..offset.saturating_add(length).min(data.len())])
}
fn header(tag: TagHash) -> Value {
    let pm = package_manager();
    match pm.get_entry(tag) {
        Some(e) => {
            json!({"tag":tag_name(tag), "reference":format!("0x{:08X}",e.reference), "file_type":e.file_type, "file_subtype":e.file_subtype, "size":e.file_size, "class_name":quicktag_core::classes::get_class_by_id(e.reference).map(|c|c.name.to_string())})
        }
        None => json!({"tag":tag_name(tag), "missing":true}),
    }
}
fn append_edges(
    rows: &mut Vec<Value>,
    source: TagHash,
    scan: &quicktag_scanner::ScanResult,
    target: Option<TagHash>,
) {
    for x in &scan.file_hashes {
        if target.is_none_or(|t| t == x.hash) {
            rows.push(json!({"source":tag_name(source), "target":tag_name(x.hash), "offset":if x.offset == u64::MAX {None} else {Some(x.offset)}, "basis":if x.offset == u64::MAX {"entry_reference"} else {"scan_match32"}}));
        }
    }
    for x in &scan.file_hashes64 {
        let resolved = package_manager()
            .lookup
            .tag64_entries
            .get(&x.hash.0)
            .map(|t| t.hash32);
        if target.is_none() || resolved == target {
            rows.push(json!({"source":tag_name(source), "target":resolved.map(tag_name), "hash64":format!("0x{:016X}",x.hash.0), "offset":x.offset, "basis":"scan_match64"}));
        }
    }
}
#[derive(Serialize)]
struct Response {
    schema_version: u32,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}
fn response(result: Result<Value>) -> Response {
    match result {
        Ok(data) => Response {
            schema_version: 1,
            ok: true,
            data: Some(data),
            error: None,
        },
        Err(e) => Response {
            schema_version: 1,
            ok: false,
            data: None,
            error: Some(format!("{e:#}")),
        },
    }
}
fn emit(result: Result<Value>) -> Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer(&mut out, &response(result))?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}
/// Consume an oversized line without retaining it, then resume at the next request.
fn read_request(reader: &mut impl BufRead) -> io::Result<Option<Result<Command>>> {
    let mut line = Vec::new();
    let mut oversized = false;
    let mut saw_input = false;
    loop {
        let bytes = reader.fill_buf()?;
        if bytes.is_empty() {
            if !saw_input {
                return Ok(None);
            }
            break;
        }
        saw_input = true;
        let newline = bytes.iter().position(|&b| b == b'\n');
        let count = newline.map_or(bytes.len(), |i| i + 1);
        if line.len().saturating_add(count) > 65536 {
            oversized = true;
        }
        if !oversized {
            line.extend_from_slice(&bytes[..count]);
        }
        reader.consume(count);
        if newline.is_some() {
            break;
        }
    }
    Ok(Some(if oversized {
        Err(anyhow::anyhow!("request exceeds 64 KiB"))
    } else {
        serde_json::from_slice(&line).map_err(anyhow::Error::from)
    }))
}

fn run(args: Args) -> Result<bool> {
    let pm = PackageManager::new(
        args.packages.to_string_lossy().into_owned(),
        args.game_version,
        None,
    )?;
    tiger_pkg::initialize_package_manager(&Arc::new(pm));
    quicktag_core::classes::initialize_reference_names();
    let mut session = Session {
        cache_path: args.cache,
        cache: None,
        strings: None,
    };
    if matches!(args.command, Command::Serve) {
        let mut input = io::stdin().lock();
        loop {
            let Some(request) = read_request(&mut input)? else {
                break;
            };
            let result = request.and_then(|c| session.query(c));
            emit(result)?;
        }
        Ok(true)
    } else {
        let result = session.query(args.command);
        let ok = result.is_ok();
        emit(result)?;
        Ok(ok)
    }
}
fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    let args = Args::parse();
    match run(args) {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(e) => {
            let _ = emit(Err(e));
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn oversized_request_does_not_break_stream() {
        let input = format!("{}\n{{\"op\":\"info\"}}\n", "x".repeat(70000));
        let mut reader = io::Cursor::new(input);
        assert!(read_request(&mut reader).unwrap().unwrap().is_err());
        assert!(matches!(
            read_request(&mut reader).unwrap().unwrap().unwrap(),
            Command::Info
        ));
        assert!(read_request(&mut reader).unwrap().is_none());
    }
    #[test]
    fn tag_hash_roundtrip() {
        for value in [0x80800000, 0x81234567, 0xffffffff] {
            let tag = TagHash(value);
            assert_eq!(parse_tag(&tag_name(tag)).unwrap(), tag);
        }
        assert_eq!(parse_tag("00008080").unwrap().0, 0x80800000);
        assert!(parse_tag("8080").is_err());
        assert!(parse_tag("ZZZZZZZZ").is_err());
    }
    #[test]
    fn pagination_reports_remaining() {
        let rows = (0..5).map(|i| json!(i)).collect();
        let r = Page {
            limit: 2,
            offset: 2,
        }
        .apply(rows)
        .unwrap();
        assert_eq!(r["items"], json!([2, 3]));
        assert_eq!(r["next_offset"], 4);
        assert!(
            Page {
                limit: 0,
                offset: 0
            }
            .apply(vec![])
            .is_err()
        );
        assert!(
            Page {
                limit: 201,
                offset: 0
            }
            .apply(vec![])
            .is_err()
        );
        assert_eq!(
            Page {
                limit: 20,
                offset: usize::MAX
            }
            .apply(vec![json!(1)])
            .unwrap()["next_offset"],
            Value::Null
        );
    }
    #[test]
    fn bytes_boundaries() {
        assert_eq!(byte_range(&[1, 2, 3], 1, usize::MAX).unwrap(), &[2, 3]);
        assert_eq!(byte_range(&[1], 1, 3).unwrap(), &[]);
        assert!(byte_range(&[1], 2, 1).is_err());
    }
    #[test]
    fn unicode_clipping() {
        let (text, truncated) = clipped(&"한".repeat(241));
        assert_eq!(text.chars().count(), 240);
        assert!(truncated);
    }
    #[test]
    fn jsonl_defaults_and_errors() {
        let c: Command = serde_json::from_str(r#"{"op":"refs","hash":"00008080"}"#).unwrap();
        assert!(matches!(
            c,
            Command::Refs {
                direction: Direction::Outgoing,
                page: Page {
                    limit: 20,
                    offset: 0
                },
                ..
            }
        ));
        assert!(
            serde_json::from_str::<Command>(r#"{"op":"bytes","hash":"00008080","length":-1}"#)
                .is_err()
        );
        assert!(serde_json::from_str::<Command>(r#"{"op":"unknown"}"#).is_err());
        assert!(!response(Err(anyhow::anyhow!("test"))).ok);
    }
}
