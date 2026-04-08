//! Binary HTTP codec for the MOTU USB protocol.
//!
//! The MOTU device uses a compact binary serialization for HTTP requests and
//! responses — NOT raw HTTP text. This module handles encoding requests and
//! decoding responses in that format.

use crate::error::{MotuError, Result};
use crate::types::{Method, Request, Response};

// ─── Helpers ────────────────────────────────────────────────────────────────

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    if offset + 4 > data.len() {
        return Err(MotuError::Codec(format!(
            "read_u32: offset {offset} + 4 exceeds data length {}",
            data.len()
        )));
    }
    Ok(u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

fn write_u32(buf: &mut Vec<u8>, val: u32) {
    buf.extend_from_slice(&val.to_le_bytes());
}

fn write_length_prefixed_str(buf: &mut Vec<u8>, s: &str) {
    write_u32(buf, s.len() as u32);
    buf.extend_from_slice(s.as_bytes());
}

fn read_length_prefixed_str(data: &[u8], offset: &mut usize) -> Result<String> {
    let len = read_u32(data, *offset)? as usize;
    *offset += 4;
    if *offset + len > data.len() {
        return Err(MotuError::Codec(format!(
            "string at offset {}: length {len} exceeds data",
            *offset - 4
        )));
    }
    let s = std::str::from_utf8(&data[*offset..*offset + len])
        .map_err(|e| MotuError::Codec(format!("invalid UTF-8: {e}")))?
        .to_string();
    *offset += len;
    Ok(s)
}

#[allow(dead_code)] // Used in tests
pub(crate) fn read_kv_pairs(data: &[u8], offset: &mut usize) -> Result<Vec<(String, String)>> {
    let count = read_u32(data, *offset)? as usize;
    *offset += 4;
    let mut pairs = Vec::with_capacity(count);
    for _ in 0..count {
        let name = read_length_prefixed_str(data, offset)?;
        let value = read_length_prefixed_str(data, offset)?;
        pairs.push((name, value));
    }
    Ok(pairs)
}

// ─── Request Encoding ───────────────────────────────────────────────────────

/// Encode an HTTP request into the MOTU binary format.
///
/// Layout:
/// ```text
/// u32 version=1 | u32 flags=0 | u32 N (size of everything after preamble,
///                                       excluding body)
/// u32 method_len + method | u32 path_len + path
/// u32 num_headers [u32 name_len + name + u32 val_len + val] × n
/// u32 num_params  [u32 name_len + name + u32 val_len + val] × n
/// [body bytes]
/// ```
pub fn encode_request(req: &Request) -> Vec<u8> {
    // Build the "after preamble" section (method + path + headers + params)
    let mut inner = Vec::with_capacity(256);

    // Method
    let method_str = req.method.as_str();
    write_length_prefixed_str(&mut inner, method_str);

    // Path
    write_length_prefixed_str(&mut inner, &req.path);

    // Headers
    write_u32(&mut inner, req.headers.len() as u32);
    for (name, val) in &req.headers {
        write_length_prefixed_str(&mut inner, name);
        write_length_prefixed_str(&mut inner, val);
    }

    // Query parameters
    write_u32(&mut inner, req.params.len() as u32);
    for (name, val) in &req.params {
        write_length_prefixed_str(&mut inner, name);
        write_length_prefixed_str(&mut inner, val);
    }

    // N = size of inner section (method + path + headers + params), excluding body
    let n = inner.len();

    // Assemble the full payload
    let mut payload = Vec::with_capacity(12 + n + req.body.len());
    write_u32(&mut payload, 1); // version
    write_u32(&mut payload, 0); // flags
    write_u32(&mut payload, n as u32); // N
    payload.extend_from_slice(&inner);
    payload.extend_from_slice(&req.body);

    payload
}

/// Decode a binary-encoded HTTP response.
///
/// Layout:
/// ```text
/// u32 version=1 | u32 flags=0 | u32 N (size of status+headers section ONLY)
/// u32 status_code | u32 num_headers
/// [u32 name_len + name + u32 val_len + val] × num_headers
/// [body at offset 12+N]
/// ```
pub fn decode_response(payload: &[u8]) -> Result<Response> {
    if payload.len() < 20 {
        return Err(MotuError::Codec(format!(
            "response too short: {} bytes (need ≥20)",
            payload.len()
        )));
    }

    let _version = read_u32(payload, 0)?;
    let _flags = read_u32(payload, 4)?;
    let n = read_u32(payload, 8)? as usize;

    let status = read_u32(payload, 12)?;
    let num_headers = read_u32(payload, 16)? as usize;

    let mut offset = 20;
    let mut headers = Vec::with_capacity(num_headers);
    for _ in 0..num_headers {
        let name = read_length_prefixed_str(payload, &mut offset)?;
        let value = read_length_prefixed_str(payload, &mut offset)?;
        headers.push((name, value));
    }

    // Body starts at 12 + N
    let body_start = 12 + n;
    let body = if body_start < payload.len() {
        payload[body_start..].to_vec()
    } else {
        Vec::new()
    };

    Ok(Response {
        status,
        headers,
        body,
    })
}

// ─── MOTU POST body envelope ────────────────────────────────────────────────

/// Encode a MOTU binary POST body.
///
/// All datastore POSTs use a binary KV envelope around the JSON value,
/// as observed in the Windows driver capture:
///
/// ```text
/// u32 remaining_len   (= 4 + key.len() + 4 + value.len())
/// u32 key_len + key   ("json")
/// u32 val_len + val   (e.g. {"value": "win"})
/// ```
///
/// Sending the raw JSON bytes without this wrapper causes `MOTUAVBController`
/// to misread the first 4 bytes as a huge allocation size → `std::bad_alloc`.
pub fn encode_motu_post_body(key: &[u8], value: &[u8]) -> Vec<u8> {
    // remaining_len covers everything after the first u32
    let remaining = 4usize + key.len() + 4 + value.len();
    let mut body = Vec::with_capacity(4 + remaining);
    write_u32(&mut body, remaining as u32);
    write_u32(&mut body, key.len() as u32);
    body.extend_from_slice(key);
    write_u32(&mut body, value.len() as u32);
    body.extend_from_slice(value);
    body
}

/// Decode a MOTU binary POST body, returning the value bytes.
///
/// Inverse of [`encode_motu_post_body`]. Used by the device simulator to
/// extract the JSON payload from an incoming POST request.
pub fn decode_motu_post_body(body: &[u8]) -> Result<Vec<u8>> {
    if body.len() < 12 {
        return Err(MotuError::Codec(format!(
            "MOTU POST body too short: {} bytes (need ≥12)",
            body.len()
        )));
    }
    // Skip u32 remaining_len, read the key length, then skip the key.
    let key_len = read_u32(body, 4)? as usize;
    let val_len_offset = 8 + key_len;
    if val_len_offset + 4 > body.len() {
        return Err(MotuError::Codec(
            "MOTU POST body: key overflows data".to_string(),
        ));
    }
    let val_len = read_u32(body, val_len_offset)? as usize;
    let val_start = val_len_offset + 4;
    if val_start + val_len > body.len() {
        return Err(MotuError::Codec(
            "MOTU POST body: value overflows data".to_string(),
        ));
    }
    Ok(body[val_start..val_start + val_len].to_vec())
}

// ─── Server-side codec (used by DeviceSimulator) ────────────────────────────

/// Decode a binary-encoded HTTP request sent by the host.
///
/// Inverse of [`encode_request`]. Used by the device simulator to parse
/// incoming frames from the host.
///
/// Layout:
/// ```text
/// u32 version=1 | u32 flags=0 | u32 N (inner section size, excludes body)
/// u32 method_len + method | u32 path_len + path
/// u32 num_headers [u32 name_len + name + u32 val_len + val] × n
/// u32 num_params  [u32 name_len + name + u32 val_len + val] × n
/// [body at offset 12+N]
/// ```
pub fn decode_request(payload: &[u8]) -> Result<Request> {
    if payload.len() < 12 {
        return Err(MotuError::Codec(format!(
            "request payload too short: {} bytes (need ≥12)",
            payload.len()
        )));
    }

    let _version = read_u32(payload, 0)?;
    let _flags = read_u32(payload, 4)?;
    let n = read_u32(payload, 8)? as usize;

    let mut offset = 12;
    let method_str = read_length_prefixed_str(payload, &mut offset)?;
    let path = read_length_prefixed_str(payload, &mut offset)?;

    let num_headers = read_u32(payload, offset)? as usize;
    offset += 4;
    let mut headers = Vec::with_capacity(num_headers);
    for _ in 0..num_headers {
        let name = read_length_prefixed_str(payload, &mut offset)?;
        let value = read_length_prefixed_str(payload, &mut offset)?;
        headers.push((name, value));
    }

    let num_params = read_u32(payload, offset)? as usize;
    offset += 4;
    let mut params = Vec::with_capacity(num_params);
    for _ in 0..num_params {
        let name = read_length_prefixed_str(payload, &mut offset)?;
        let value = read_length_prefixed_str(payload, &mut offset)?;
        params.push((name, value));
    }

    let body_start = 12 + n;
    let body = if body_start < payload.len() {
        payload[body_start..].to_vec()
    } else {
        Vec::new()
    };

    let method = match method_str.as_str() {
        "GET" => Method::Get,
        "POST" => Method::Post,
        "PATCH" => Method::Patch,
        "DELETE" => Method::Delete,
        "PUT" => Method::Put,
        other => {
            return Err(MotuError::Codec(format!("unknown HTTP method: {other:?}")));
        }
    };

    Ok(Request { method, path, headers, params, body })
}

/// Encode an HTTP response into the MOTU binary format.
///
/// Inverse of [`decode_response`]. Used by the device simulator to send
/// responses back to the host.
///
/// Layout:
/// ```text
/// u32 version=1 | u32 flags=0 | u32 N (status+headers section size ONLY)
/// u32 status_code | u32 num_headers
/// [u32 name_len + name + u32 val_len + val] × num_headers
/// [body bytes starting at offset 12+N]
/// ```
pub fn encode_response(resp: &Response) -> Vec<u8> {
    // Build the status + headers inner section.
    let mut inner = Vec::new();
    write_u32(&mut inner, resp.status);
    write_u32(&mut inner, resp.headers.len() as u32);
    for (name, val) in &resp.headers {
        write_length_prefixed_str(&mut inner, name);
        write_length_prefixed_str(&mut inner, val);
    }
    let n = inner.len() as u32;

    let mut payload = Vec::with_capacity(12 + inner.len() + resp.body.len());
    write_u32(&mut payload, 1);  // version
    write_u32(&mut payload, 0);  // flags
    write_u32(&mut payload, n);  // N = size of inner section
    payload.extend_from_slice(&inner);
    payload.extend_from_slice(&resp.body);
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_post_request() {
        // From capture: POST /datastore/host/os with auth header and JSON body
        let req = Request {
            method: Method::Post,
            path: "/datastore/host/os".to_string(),
            headers: vec![(
                "Unsecure-Auth-MOTU".to_string(),
                "unicorn666".to_string(),
            )],
            params: Vec::new(),
            body: br#"{"value": "win"}"#.to_vec(),
        };

        let encoded = encode_request(&req);

        // Verify structure
        let version = read_u32(&encoded, 0).unwrap();
        assert_eq!(version, 1);
        let flags = read_u32(&encoded, 4).unwrap();
        assert_eq!(flags, 0);

        // Verify known bytes from capture at offset 12+:
        // u32 method_len=4, "POST", u32 path_len=18, "/datastore/host/os"
        let method_len = read_u32(&encoded, 12).unwrap();
        assert_eq!(method_len, 4);
        assert_eq!(&encoded[16..20], b"POST");

        let path_len = read_u32(&encoded, 20).unwrap();
        assert_eq!(path_len, 18);
        assert_eq!(&encoded[24..42], b"/datastore/host/os");

        // Verify encoding is substantial and contains expected components
        assert!(encoded.len() > 40, "encoded request should be substantial");

        // Verify body is after the inner section at offset 12+N
        let n = read_u32(&encoded, 8).unwrap() as usize;
        let body = &encoded[12 + n..];
        assert_eq!(body, br#"{"value": "win"}"#);
    }

    #[test]
    fn test_encode_get_request_with_params() {
        let req = Request::get("/datastore")
            .header("If-None-Match", "0");

        let encoded = encode_request(&req);

        let version = read_u32(&encoded, 0).unwrap();
        assert_eq!(version, 1);

        let method_len = read_u32(&encoded, 12).unwrap();
        assert_eq!(method_len, 3);
        assert_eq!(&encoded[16..19], b"GET");

        let path_len = read_u32(&encoded, 19).unwrap();
        assert_eq!(path_len, 10);
        assert_eq!(&encoded[23..33], b"/datastore");
    }

    #[test]
    fn test_decode_204_response() {
        // From capture: 204 response with CORS headers, no body.
        // Reconstructed from the analyze output:
        //   status=204, headers: Access-Control-Allow-Headers: Authorization,
        //   Access-Control-Allow-Origin: *, Access-Control-Expose-Headers: Access-Control-Allow-Headers
        let mut payload = Vec::new();
        write_u32(&mut payload, 1); // version
        write_u32(&mut payload, 0); // flags

        // Build headers section to measure N
        let mut headers_section = Vec::new();
        write_u32(&mut headers_section, 204); // status
        write_u32(&mut headers_section, 3);   // num_headers

        // Header 1
        write_length_prefixed_str(&mut headers_section, "Access-Control-Allow-Headers");
        write_length_prefixed_str(&mut headers_section, "Authorization");
        // Header 2
        write_length_prefixed_str(&mut headers_section, "Access-Control-Allow-Origin");
        write_length_prefixed_str(&mut headers_section, "*");
        // Header 3
        write_length_prefixed_str(&mut headers_section, "Access-Control-Expose-Headers");
        write_length_prefixed_str(&mut headers_section, "Access-Control-Allow-Headers");

        write_u32(&mut payload, headers_section.len() as u32); // N
        payload.extend_from_slice(&headers_section);

        let resp = decode_response(&payload).unwrap();
        assert_eq!(resp.status, 204);
        assert_eq!(resp.headers.len(), 3);
        assert_eq!(resp.headers[0].0, "Access-Control-Allow-Headers");
        assert_eq!(resp.headers[0].1, "Authorization");
        assert_eq!(resp.headers[1].1, "*");
        assert!(resp.body.is_empty());
    }

    #[test]
    fn test_decode_200_response_with_body() {
        let mut payload = Vec::new();
        write_u32(&mut payload, 1); // version
        write_u32(&mut payload, 0); // flags

        let mut headers_section = Vec::new();
        write_u32(&mut headers_section, 200); // status
        write_u32(&mut headers_section, 2);   // num_headers
        write_length_prefixed_str(&mut headers_section, "Content-Type");
        write_length_prefixed_str(&mut headers_section, "application/json");
        write_length_prefixed_str(&mut headers_section, "ETag");
        write_length_prefixed_str(&mut headers_section, "6126");

        write_u32(&mut payload, headers_section.len() as u32); // N
        payload.extend_from_slice(&headers_section);

        let body = br#"{"key":"value"}"#;
        payload.extend_from_slice(body);

        let resp = decode_response(&payload).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.len(), 2);
        assert_eq!(resp.header("Content-Type"), Some("application/json"));
        assert_eq!(resp.header("ETag"), Some("6126"));
        assert_eq!(resp.body, body);
    }

    #[test]
    fn test_roundtrip_request_fields() {
        let req = Request::post("/datastore/host/os", br#"{"value":"linux"}"#.to_vec())
            .header("Unsecure-Auth-MOTU", "unicorn666")
            .param("json", r#"{"value":"linux"}"#);

        let encoded = encode_request(&req);
        assert!(encoded.len() > 12);

        // Manually decode to verify
        let version = read_u32(&encoded, 0).unwrap();
        assert_eq!(version, 1);
        let flags = read_u32(&encoded, 4).unwrap();
        assert_eq!(flags, 0);
        let n = read_u32(&encoded, 8).unwrap() as usize;

        let mut off = 12;
        let method = read_length_prefixed_str(&encoded, &mut off).unwrap();
        assert_eq!(method, "POST");

        let path = read_length_prefixed_str(&encoded, &mut off).unwrap();
        assert_eq!(path, "/datastore/host/os");

        let headers = read_kv_pairs(&encoded, &mut off).unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0], ("Unsecure-Auth-MOTU".to_string(), "unicorn666".to_string()));

        let params = read_kv_pairs(&encoded, &mut off).unwrap();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].0, "json");

        // N = inner section size (method + path + headers + params), body follows at 12+N
        assert_eq!(off, 12 + n);

        let body = &encoded[12 + n..];
        assert_eq!(body, br#"{"value":"linux"}"#);
    }

    #[test]
    fn test_encode_matches_capture_exactly() {
        // Exact captured payload (bytes 32+ of frame) from the POST /datastore/host/os
        // request in capture-windows-boot.jsonl. The body in the capture was a binary-
        // encoded key-value pair (json={"value": "win"}), which the MOTU Windows driver
        // constructs. We pass the raw body bytes as-is.
        let body_bytes: Vec<u8> = {
            let mut b = Vec::new();
            // u32 28 (remaining body length)
            b.extend_from_slice(&28u32.to_le_bytes());
            // u32 4 + "json"
            b.extend_from_slice(&4u32.to_le_bytes());
            b.extend_from_slice(b"json");
            // u32 16 + {"value": "win"}
            b.extend_from_slice(&16u32.to_le_bytes());
            b.extend_from_slice(br#"{"value": "win"}"#);
            b
        };

        let req = Request {
            method: Method::Post,
            path: "/datastore/host/os".to_string(),
            headers: vec![(
                "Unsecure-Auth-MOTU".to_string(),
                "unicorn666".to_string(),
            )],
            params: Vec::new(),
            body: body_bytes,
        };

        let encoded = encode_request(&req);

        // Expected payload from capture (118 bytes)
        let expected: Vec<u8> = vec![
            // version=1, flags=0, N=74
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00,
            // method_len=4, "POST"
            0x04, 0x00, 0x00, 0x00, 0x50, 0x4f, 0x53, 0x54,
            // path_len=18, "/datastore/host/os"
            0x12, 0x00, 0x00, 0x00,
            0x2f, 0x64, 0x61, 0x74, 0x61, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2f, 0x68,
            0x6f, 0x73, 0x74, 0x2f, 0x6f, 0x73,
            // num_headers=1
            0x01, 0x00, 0x00, 0x00,
            // header_name_len=18, "Unsecure-Auth-MOTU"
            0x12, 0x00, 0x00, 0x00,
            0x55, 0x6e, 0x73, 0x65, 0x63, 0x75, 0x72, 0x65, 0x2d, 0x41, 0x75, 0x74,
            0x68, 0x2d, 0x4d, 0x4f, 0x54, 0x55,
            // header_val_len=10, "unicorn666"
            0x0a, 0x00, 0x00, 0x00,
            0x75, 0x6e, 0x69, 0x63, 0x6f, 0x72, 0x6e, 0x36, 0x36, 0x36,
            // num_params=0
            0x00, 0x00, 0x00, 0x00,
            // body: u32 28, u32 4 "json", u32 16 {"value": "win"}
            0x1c, 0x00, 0x00, 0x00,
            0x04, 0x00, 0x00, 0x00, 0x6a, 0x73, 0x6f, 0x6e,
            0x10, 0x00, 0x00, 0x00,
            0x7b, 0x22, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x22, 0x3a, 0x20, 0x22, 0x77,
            0x69, 0x6e, 0x22, 0x7d,
        ];

        assert_eq!(encoded, expected, "encoded payload must match capture exactly");
    }
}
