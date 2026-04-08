//! In-memory datastore — Rust equivalent of `DataStoreIPC` in tamio.c.
//!
//! The MOTU device maintains a flat key/value database — `DataStoreIPC` —
//! that is exposed over HTTP as a JSON object at `GET /datastore`.  Clients
//! subscribe to changes via the ETag long-poll pattern:
//!
//! 1. `GET /datastore` with `If-None-Match: 0` → **200 OK** + full JSON +
//!    `ETag: <n>` header.
//! 2. `GET /datastore` with `If-None-Match: <n>` (current ETag) → device
//!    **blocks** until the store changes, then replies **200 OK** with the
//!    delta (changed keys only) + new `ETag`.
//! 3. If nothing changes within ~30 s the device responds with **304 Not
//!    Modified** and the client re-polls.
//!
//! ## DataStoreIPC functions mirrored here
//!
//! | tamio.c function (line)         | `Datastore` method            |
//! |---------------------------------|-------------------------------|
//! | `DataStoreIPC::SetInt`  (1905)  | `set(key, DataValue::Int)`    |
//! | `DataStoreIPC::SetReal` (4391)  | `set(key, DataValue::Float)`  |
//! | `DataStoreIPC::SetString` (2479)| `set(key, DataValue::String)` |
//! | `DataStoreIPC::Init`    (4190)  | `Datastore::with_defaults()`  |
//! | `DataStoreIPC::Reset`   (4276)  | `reset()`                     |

use std::collections::HashMap;
use tokio::sync::watch;

/// A leaf value in the datastore.
///
/// The MOTU datastore holds three scalar types: integer, float, and string.
/// Booleans are represented as integers (0 / 1).
#[derive(Debug, Clone, PartialEq)]
pub enum DataValue {
    /// 64-bit signed integer (covers i32 / bool).
    Int(i64),
    /// 64-bit IEEE 754 float.
    Float(f64),
    /// UTF-8 string.
    String(String),
}

impl DataValue {
    /// Serialise the value to a JSON fragment (no quotes for numeric types).
    pub fn to_json(&self) -> String {
        match self {
            Self::Int(n) => n.to_string(),
            Self::Float(f) => {
                // Use the same compact representation as the device: no
                // trailing zeros, but always include a decimal point so the
                // value stays numeric in any JSON parser.
                let s = format!("{f}");
                if s.contains('.') { s } else { format!("{f:.1}") }
            }
            Self::String(s) => {
                // Minimal JSON string escaping (backslash, double-quote, controls).
                let mut out = String::with_capacity(s.len() + 2);
                out.push('"');
                for c in s.chars() {
                    match c {
                        '"' => out.push_str(r#"\""#),
                        '\\' => out.push_str(r"\\"),
                        '\n' => out.push_str(r"\n"),
                        '\r' => out.push_str(r"\r"),
                        '\t' => out.push_str(r"\t"),
                        c if (c as u32) < 0x20 => {
                            out.push_str(&format!("\\u{:04x}", c as u32));
                        }
                        c => out.push(c),
                    }
                }
                out.push('"');
                out
            }
        }
    }
}

impl From<i64> for DataValue {
    fn from(n: i64) -> Self { Self::Int(n) }
}
impl From<i32> for DataValue {
    fn from(n: i32) -> Self { Self::Int(n as i64) }
}
impl From<f64> for DataValue {
    fn from(f: f64) -> Self { Self::Float(f) }
}
impl From<&str> for DataValue {
    fn from(s: &str) -> Self { Self::String(s.to_string()) }
}
impl From<String> for DataValue {
    fn from(s: String) -> Self { Self::String(s) }
}

// ─── Datastore ───────────────────────────────────────────────────────────────

/// In-memory equivalent of `DataStoreIPC`.
///
/// Thread-safe via external `tokio::sync::Mutex<Datastore>` (the caller wraps
/// this in `Arc<Mutex<Datastore>>`).  Long-poll clients subscribe to changes
/// via [`Datastore::subscribe`], which returns a
/// [`tokio::sync::watch::Receiver`] that is notified on each [`set`].
///
/// [`set`]: Datastore::set
pub struct Datastore {
    /// Flat key→value map.  Keys use the same slash-separated path notation as
    /// the MOTU HTTP API (e.g. `"avb/0001f2fffe00a4df/model_name"`).
    entries: HashMap<String, DataValue>,
    /// Monotonically increasing generation counter.  Incremented on every
    /// successful [`set`] or [`patch_json`] call.
    ///
    /// [`set`]: Datastore::set
    /// [`patch_json`]: Datastore::patch_json
    etag: u64,
    /// Broadcast channel — notified with the new ETag after every mutation.
    /// Receivers created by [`subscribe`] sleep until the value changes.
    ///
    /// [`subscribe`]: Datastore::subscribe
    notify: watch::Sender<u64>,
}

impl Datastore {
    /// Create an empty datastore.
    pub fn new() -> Self {
        let (tx, _) = watch::channel(1u64);
        Self {
            entries: HashMap::new(),
            etag: 1,
            notify: tx,
        }
    }

    /// Create a datastore pre-populated with the minimal key set that the
    /// Windows driver expects to find on first `GET /datastore`.
    ///
    /// Values are taken from the live 828ES capture
    /// (`captures/02-get-datastore-response.json`).
    pub fn with_defaults() -> Self {
        let mut ds = Self::new();

        // ── Host state ─────────────────────────────────────────────────────
        // Initialised to "mac" by FUN_000777c8 / InitExtendedData.
        // The connect() handshake immediately overwrites this with "win".
        ds.insert("host/os", "mac");
        ds.insert("host/connected", 0i64);
        ds.insert("host/uid", "");
        ds.insert("host/firmware_version", "");
        // Phase-2 registration paths — populated by connect_via POSTs.
        ds.insert("host/driver_version", "");
        ds.insert("host/mode", "USB2");
        ds.insert("host/win/buffer_sizes_1x", "");
        ds.insert("host/win/safety_offsets_1x", "");

        // ── AVB device identity (Phase-3 identity GETs) ────────────────────
        // avb/devs: the EUI-64 list returned by GET /datastore/avb/devs.
        // Must match the EUI prefix used for all avb/<eui>/* keys below.
        let eui = "0001f2fffe00a4df";
        ds.insert("avb/devs", eui);

        // host_type: "USB" or "Ethernet" (GET /datastore/host_type)
        ds.insert("host_type", "USB");

        // ── AVB entity (from capture — real 828ES serial) ──────────────────
        let eid = "avb/0001f2fffe00a4df";
        ds.insert(format!("{eid}/acquired_id"), "");
        ds.insert(format!("{eid}/master_clock/capable"), 1i64);
        ds.insert(format!("{eid}/requested_configuration"), 0i64);
        ds.insert(format!("{eid}/cfg/num"), 1i64);
        ds.insert(format!("{eid}/cfg/names"), "");
        ds.insert(format!("{eid}/entity_model_id_h32"), 16_904_704i64);
        ds.insert(format!("{eid}/entity_model_id_l32"), 15i64);
        ds.insert(format!("{eid}/firmware_version"), "1.3.4+172\n07/27/18 17:15:10");
        ds.insert(format!("{eid}/serial_number"), "");
        ds.insert(format!("{eid}/current_configuration"), 0i64);
        ds.insert(format!("{eid}/vendor_name"), "MOTU");
        ds.insert(format!("{eid}/model_name"), "828ES");
        ds.insert(format!("{eid}/entity_name"), "828ES");
        ds.insert(format!("{eid}/controller_ignore"), 0i64);
        ds.insert(format!("{eid}/cfg/0/object_name"), "");
        ds.insert(format!("{eid}/cfg/0/identify"), 0i64);
        ds.insert(
            format!("{eid}/cfg/0/sample_rates"),
            "44100:48000:88200:96000:176400:192000",
        );
        ds.insert(format!("{eid}/cfg/0/clock_sources/num"), 8i64);
        ds.insert(format!("{eid}/cfg/0/clock_source_index"), 6i64);
        ds.insert(format!("{eid}/cfg/0/sample_rate"), 48000i64);

        ds
    }

    // ── Accessors ────────────────────────────────────────────────────────────

    /// Return the current ETag (generation counter).
    pub fn etag(&self) -> u64 { self.etag }

    /// Return a receiver that fires whenever the store is mutated.
    ///
    /// The receiver's value is the new ETag after each mutation.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.notify.subscribe()
    }

    /// Look up a single key.
    pub fn get(&self, key: &str) -> Option<&DataValue> {
        self.entries.get(key)
    }

    // ── Mutation ─────────────────────────────────────────────────────────────

    /// Insert or overwrite a key without bumping the ETag or notifying
    /// subscribers.  Use this during initial population only.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<DataValue>) {
        self.entries.insert(key.into(), value.into());
    }

    /// Set a key and bump the ETag, notifying all subscribers.
    ///
    /// Mirrors `DataStoreIPC::SetInt`, `::SetReal`, and `::SetString`.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<DataValue>) {
        self.entries.insert(key.into(), value.into());
        self.etag += 1;
        let _ = self.notify.send(self.etag);
    }

    /// Remove a key and bump the ETag.
    pub fn remove(&mut self, key: &str) -> bool {
        let removed = self.entries.remove(key).is_some();
        if removed {
            self.etag += 1;
            let _ = self.notify.send(self.etag);
        }
        removed
    }

    /// Reset the store to empty, as `DataStoreIPC::Reset` (line 4276) does.
    pub fn reset(&mut self) {
        self.entries.clear();
        self.etag += 1;
        let _ = self.notify.send(self.etag);
    }

    // ── JSON serialisation ────────────────────────────────────────────────────

    /// Serialise the entire datastore to a flat JSON object.
    ///
    /// Output format mirrors the real device: a single JSON object whose keys
    /// are slash-separated paths and values are JSON strings or numbers.
    /// Keys are emitted in insertion order (HashMap iteration order is not
    /// guaranteed, but that is acceptable — the client re-parses every time).
    pub fn to_json(&self) -> String {
        let mut out = String::from("{");
        let mut first = true;
        for (k, v) in &self.entries {
            if !first { out.push(','); }
            first = false;
            out.push('"');
            out.push_str(k);
            out.push_str("\":");
            out.push_str(&v.to_json());
        }
        out.push('}');
        out
    }

    /// Serialise all keys that start with `prefix` (e.g. `"host/"`) to JSON.
    ///
    /// Returns a flat JSON object containing only the matching keys.
    pub fn subtree_json(&self, prefix: &str) -> String {
        let mut out = String::from("{");
        let mut first = true;
        for (k, v) in &self.entries {
            if !k.starts_with(prefix) { continue; }
            if !first { out.push(','); }
            first = false;
            out.push('"');
            out.push_str(k);
            out.push_str("\":");
            out.push_str(&v.to_json());
        }
        out.push('}');
        out
    }

    /// Apply a JSON `PATCH /datastore` body.
    ///
    /// The body must be a flat JSON object `{"key": value, ...}`.  Each entry
    /// is applied as a [`set`] call and bumps the ETag once per call-chain
    /// (the device increments the ETag per-key, but for the simulator a single
    /// bump per patch is sufficient).
    ///
    /// Only string and numeric (integer/float) top-level values are supported;
    /// nested objects are skipped.
    ///
    /// [`set`]: Datastore::set
    pub fn patch_json(&mut self, body: &[u8]) -> Result<usize, String> {
        let text = std::str::from_utf8(body)
            .map_err(|e| format!("PATCH body is not valid UTF-8: {e}"))?;

        let map: serde_json::Map<String, serde_json::Value> = serde_json::from_str(text)
            .map_err(|e| format!("PATCH body is not valid JSON object: {e}"))?;

        let mut count = 0usize;
        for (k, v) in map {
            let dv = match &v {
                serde_json::Value::String(s) => DataValue::String(s.clone()),
                serde_json::Value::Number(n) => {
                    if let Some(i) = n.as_i64() {
                        DataValue::Int(i)
                    } else if let Some(f) = n.as_f64() {
                        DataValue::Float(f)
                    } else {
                        continue; // skip non-representable numbers
                    }
                }
                serde_json::Value::Bool(b) => DataValue::Int(*b as i64),
                _ => continue, // skip nested objects/arrays/null
            };
            self.entries.insert(k, dv);
            count += 1;
        }

        if count > 0 {
            self.etag += 1;
            let _ = self.notify.send(self.etag);
        }

        Ok(count)
    }

    /// Parse a `POST /datastore/{path}` body and set the value.
    ///
    /// The body must be a JSON object with a `"value"` key, e.g.:
    /// `{"value": "win"}` or `{"value": 48000}`.
    ///
    /// Mirrors the pattern used by the Windows driver for all PTTH POSTs.
    pub fn post_value(&mut self, key: &str, body: &[u8]) -> Result<(), String> {
        let text = std::str::from_utf8(body)
            .map_err(|e| format!("POST body is not valid UTF-8: {e}"))?;

        let obj: serde_json::Value = serde_json::from_str(text)
            .map_err(|e| format!("POST body is not valid JSON: {e}"))?;

        let v = obj.get("value").ok_or_else(|| "no \"value\" key in POST body".to_string())?;

        let dv = match v {
            serde_json::Value::String(s) => DataValue::String(s.clone()),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() { DataValue::Int(i) }
                else if let Some(f) = n.as_f64() { DataValue::Float(f) }
                else { return Err(format!("unrepresentable number: {n}")); }
            }
            serde_json::Value::Bool(b) => DataValue::Int(*b as i64),
            other => return Err(format!("unsupported value type: {other}")),
        };

        self.set(key, dv);
        Ok(())
    }
}

impl Default for Datastore {
    fn default() -> Self { Self::new() }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_json_int() {
        let mut ds = Datastore::new();
        ds.insert("host/connected", 0i64);
        let json = ds.to_json();
        assert_eq!(json, r#"{"host/connected":0}"#);
    }

    #[test]
    fn test_to_json_string() {
        let mut ds = Datastore::new();
        ds.insert("host/os", "mac");
        let json = ds.to_json();
        assert_eq!(json, r#"{"host/os":"mac"}"#);
    }

    #[test]
    fn test_to_json_float() {
        let mut ds = Datastore::new();
        ds.insert("gain", 0.5f64);
        let json = ds.to_json();
        assert!(json.contains("0.5"), "json: {json}");
    }

    #[test]
    fn test_set_bumps_etag() {
        let mut ds = Datastore::new();
        let initial = ds.etag();
        ds.set("host/os", "win");
        assert!(ds.etag() > initial);
    }

    #[test]
    fn test_patch_json() {
        let mut ds = Datastore::new();
        let body = br#"{"host/os": "win", "host/connected": 1}"#;
        let count = ds.patch_json(body).unwrap();
        assert_eq!(count, 2);
        assert_eq!(ds.get("host/os"), Some(&DataValue::String("win".into())));
        assert_eq!(ds.get("host/connected"), Some(&DataValue::Int(1)));
    }

    #[test]
    fn test_post_value_string() {
        let mut ds = Datastore::new();
        ds.post_value("host/os", br#"{"value": "win"}"#).unwrap();
        assert_eq!(ds.get("host/os"), Some(&DataValue::String("win".into())));
    }

    #[test]
    fn test_post_value_int() {
        let mut ds = Datastore::new();
        ds.post_value("mix/main/volume", br#"{"value": 48000}"#).unwrap();
        assert_eq!(ds.get("mix/main/volume"), Some(&DataValue::Int(48000)));
    }

    #[test]
    fn test_with_defaults_has_model_name() {
        let ds = Datastore::with_defaults();
        assert_eq!(
            ds.get("avb/0001f2fffe00a4df/model_name"),
            Some(&DataValue::String("828ES".into()))
        );
    }

    #[test]
    fn test_json_string_escaping() {
        let v = DataValue::String("line1\nline2".into());
        assert_eq!(v.to_json(), r#""line1\nline2""#);
    }
}
