use std::fmt;

/// HTTP method for MOTU requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Patch,
    Delete,
    Put,
}

impl Method {
    pub fn as_str(&self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Patch => "PATCH",
            Method::Delete => "DELETE",
            Method::Put => "PUT",
        }
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An HTTP request to send to the MOTU device.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: Method,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub params: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// Create a GET request to the given path.
    pub fn get(path: impl Into<String>) -> Self {
        Self {
            method: Method::Get,
            path: path.into(),
            headers: Vec::new(),
            params: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Create a POST request to the given path with a body.
    pub fn post(path: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            method: Method::Post,
            path: path.into(),
            headers: Vec::new(),
            params: Vec::new(),
            body: body.into(),
        }
    }

    /// Add a header to the request.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Add a query parameter to the request.
    pub fn param(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.params.push((name.into(), value.into()));
        self
    }
}

/// An HTTP response from the MOTU device.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u32,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// Get a header value by name (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Get the body as a UTF-8 string.
    pub fn body_text(&self) -> std::result::Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.body)
    }
}

/// MOTU protocol message type (4cc identifier).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// Full HTTP request/response channel.
    Ptth,
    /// Lightweight long-poll channel (GET /datastore with ETag).
    Nrek,
}

impl MessageType {
    pub const PTTH_BYTES: &[u8; 4] = b"PTTH";
    pub const NREK_BYTES: &[u8; 4] = b"NREK";

    pub fn as_bytes(&self) -> &[u8; 4] {
        match self {
            MessageType::Ptth => Self::PTTH_BYTES,
            MessageType::Nrek => Self::NREK_BYTES,
        }
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 4 {
            return None;
        }
        match &b[..4] {
            b"PTTH" => Some(MessageType::Ptth),
            b"NREK" => Some(MessageType::Nrek),
            _ => None,
        }
    }
}

/// Outer frame flag byte values.
pub mod flags {
    /// Session open (first packet from host).
    pub const CONNECT: u8 = 0x82;
    /// Keepalive from host.
    pub const PING: u8 = 0x81;
    /// Data frame from host.
    pub const DATA_OUT: u8 = 0x80;
    /// Data frame or PONG from device.
    pub const DATA_IN: u8 = 0x00;
}

/// MOTU magic bytes: "MOTU" stored as little-endian "UTOM".
pub const MOTU_MAGIC: &[u8; 4] = b"UTOM";

/// Inner header constant (always 8).
pub const INNER_HDR_VALUE: u32 = 8;

/// Decoded frame from the device.
#[derive(Debug, Clone)]
pub enum Frame {
    /// PONG response (echoes the host's seq).
    Pong { echoed_seq: u8 },
    /// Data frame with decoded inner header.
    Data {
        seq: u8,
        msg_type: MessageType,
        session_id: u32,
        msg_seq: u32,
        chunk_idx: u16,
        payload: Vec<u8>,
    },
}
