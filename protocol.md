# This could be wrong

Protocol summary (from usbmon capture + HAR reverse engineering):
  ┌──────────────────────────────────────────────────────────────────┐
  │ Outer frame (4 bytes, every packet)                              │
  │  [0]    seq       u8    — counter; OUT: 0x20+, IN: 0x54+        │
  │  [1]    flags     u8    — 0x80=data OUT, 0x81=PING,             │
  │                           0x82=CONNECT (session open), 0x00=IN  │
  │  [2-3]  total_len u16LE — full packet length                     │
  ├──────────────────────────────────────────────────────────────────┤
  │ CONNECT (OUT, 4 bytes):  [seq] 0x82 0x04 0x00  ← first packet   │
  │ PING    (OUT, 4 bytes):  [seq] 0x81 0x04 0x00                   │
  │ ACK     (IN,  8 bytes):  [seq] 0x00 0x08 0x00  × 2 (echoes seq)│
  ├──────────────────────────────────────────────────────────────────┤
  │ Data frame header (bytes 4-31, both msg types):                  │
  │  [4-7]   msg_type    4cc  — b"NREK" or b"PTTH"                  │
  │  [8-11]  session_id  u32  — random nonce per channel             │
  │  [12-15] msg_seq     u32  — per-channel counter (LE)             │
  │  [16-19] direction   u32  — 1=OUT (request), 0=IN (response)     │
  │  [20-21] chunk_idx   u16  — always 0 (inner header only appears once,   │
  │                             in the first USB packet of each transfer)    │
  │  [22-23] payload_len u16  — bytes of payload in the FULL logical frame,  │
  │                             = total_len − 32 (4 outer + 28 inner)        │
  │  [24-27] motu_magic  4cc  — b"UTOM" (MOTU little-endian)        │
  │  [28-31] inner_hdr   u32  — always 8                             │
  │  [32…]   payload          — binary-serialized HTTP (see codec)   │
  └──────────────────────────────────────────────────────────────────┘
  Large IN responses (e.g. initial /datastore dump ≥ 4 KiB) are delivered
  as a single USB bulk transfer spanning multiple 512-byte USB packets.
  The outer+inner header appears only in the FIRST packet; subsequent packets
  are raw body continuation with no headers.
  libusb (via pyusb read()) reassembles these automatically: a single
  read(EP_BULK_IN, 131072) call returns the complete transfer once the device
  signals end-of-transfer with a short packet or ZLP.

Payload format (NOT raw HTTP; both PTTH and NREK share this encoding):
  REQUEST  (OUT, bytes 32…):
    u32 1 | u32 0 | u32 N | u32 method_len+method | u32 path_len+path
    u32 num_headers  [u32 name_len+name + u32 val_len+val] × n
    u32 num_params   [u32 name_len+name + u32 val_len+val] × n  | body
  RESPONSE (IN, bytes 32…total_len-4):
    u32 1 | u32 0 | u32 N (headers section) | u32 status | u32 num_headers
    [u32 name_len+name + u32 val_len+val] × n  | body
  IN frames append a 4-byte footer (outer header copy) at total_len-4.