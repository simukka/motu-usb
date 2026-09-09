# How MOTU USB HTTP Access Works
The MOTU devices (828ES, M64) run embedded Linux on an ARM926EJ-S processor, 
serving an HTTP "datastore" API from an onboard web server. 

On Windows/Mac, the MOTU driver establishes a USB CDC (Communication Device Class) network interface, 
creating a virtual Ethernet link between the host and the device's internal HTTP server. 

Linux doesn't automatically know how to handle this link. 
The MOTU AVB Web API uses simple HTTP GET/POST against /datastore endpoints.

## Strategy 1: Use the AVB Ethernet Port (Easiest, Works Today)
Both the 828ES and M64 have physical AVB Ethernet ports. The Drumfix Linux driver's own documentation confirms HTTP API access via Ethernet works natively:

You can connect the device's Ethernet port to your router or directly to your Linux machine (using a static IP or link-local addressing). The HTTP API is fully functional over this path — no drivers needed. This is the fastest path to eliminate the Windows VM dependency.

However, the AVB ethernet is a closed network and is (at the moment) only for AVB devices 
in my studio. For this reason, strategy 1 is not ideal. 

## Strategy 2: Probe the USB Descriptor for a Native CDC Network Interface
MOTU may already expose a CDC-ECM, CDC-NCM, or RNDIS network interface over USB.
Linux supports all of these natively via cdc_ether or rndis_host. 

First, identify the USB interface classes:
If a CDC/RNDIS interface is present, the snd_usb_audio module may be claiming the whole device before cdc_ether can attach. You'd fix this with a udev rule:

## Strategy 3: Adapt the Existing motu-avb-usb Kernel Driver
The Drumfix/motu-avb-usb out-of-tree kernel module handles USB audio for MOTU AVB devices 
and has partial 828ES support (see issue #11). 

The driver claims all USB interfaces — it could be extended to also bind and expose the 
network interface via Linux's usbnet subsystem, publishing an eth or usb0 interface for 
HTTP API access. This would be the most complete solution for both audio and API 
access over a single USB cable.

## Strategy 4: USB Traffic Capture + Protocol Reverse Engineering
Use Wireshark with the USBPcap plugin on Windows (or usbmon on Linux with the Windows VM) to 
capture the USB bulk transfers that carry HTTP traffic. If the frames are CDC-ECM (Ethernet frames over USB), 
you can implement a minimal usbnet-based driver with the correct driver_info binding for MOTU's VID/PID pair. 
ChristopherJohnston's motu_osc_bridge and motu_websocket_bridge show exactly how the HTTP/datastore 
protocol works at the application layer once you have connectivity.

## Strategy 5: USB/IP Tunnel (Minimal VM Involvement)
If you want to keep using a VM but reduce friction, Linux's built-in usbip infrastructure lets you expose 
USB devices over TCP. You could bind the MOTU device in the VM (running MOTU drivers), then tunnel only 
the HTTP port (port 80) back to your Linux host — removing the need to actively use the VM for anything other than driver hosting


# Strategy 2 Notes

Run `sudo python3 scripts/probe-usb.py 2>&1 | tee scripts/probe-output.txt`

The key findings from the probe output:

No CDC/RNDIS interface — Strategy 2 is a dead end. The devices only expose class 0xFF (Vendor Specific) interfaces.

The vendor bulk interface on both devices:

M64: Interface 3 (FF/04/01) — EP3 IN (0x83), EP4 OUT (0x04), bulk, 512 bytes
828ES: Interface 5 (FF/04/01) — EP3 IN (0x83), EP4 OUT (0x04), bulk, 512 bytes
These interfaces are unbound — snd-usb-audio isn't claiming them, so I can access them directly from userspace with libusb. There are also vendor isochronous interfaces for audio streaming.

The proto=0x01 bulk interface with a symmetric IN/OUT pair (512-byte packets) is almost certainly the HTTP transport. The isochronous proto=0x02 interfaces are vendor-mode audio. Crucially, snd-usb-audio is not claiming these — they're sitting unbound and accessible from userspace right now with no kernel driver needed.

The next step is to try sending raw HTTP directly over those bulk endpoints using pyusb. If MOTU uses bare HTTP-over-bulk (no framing), the web UI will respond immediately. If there's framing, we'll use usbmon to decode it.

# Strategy 4 Notes

## Step 1 — try raw HTTP over bulk first (fastest path)
```
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install pyusb
sudo .venv/bin/python3 scripts/bulk-probe.py
```

```
════════════════════════════════════════════════════
  M64  (serial 0001f2fffe0063b4)
════════════════════════════════════════════════════
[INFO]  Found vendor bulk interface #3: EP_OUT=0x04  EP_IN=0x83
[OK]    Claimed interface 3

[INFO]  ── Trying: GET /datastore  (HTTP/1.0, no framing)
[INFO]     Sending 52 bytes →
   b'GET /datastore HTTP/1.0\r\nHost: motu\r\nAccept: */*\r\n\r\n'
[INFO]     Wrote 52 bytes
[WARN]     No response received within timeout

[INFO]  ── Trying: GET /  (HTTP/1.0, no framing)
[INFO]     Sending 43 bytes →
   b'GET / HTTP/1.0\r\nHost: motu\r\nAccept: */*\r\n\r\n'
[INFO]     Wrote 43 bytes
[WARN]     No response received within timeout

[INFO]  ── Trying: GET /datastore  (HTTP/1.1)
[INFO]     Sending 71 bytes →
   b'GET /datastore HTTP/1.1\r\nHost: motu\r\nAccept: */*\r\nConnection: close\r\n\r\n'
[INFO]     Wrote 71 bytes
[WARN]     No response received within timeout

[WARN]  No HTTP response from any request variant.
[WARN]  Next step: capture USB traffic with usbmon while the Windows VM accesses the web UI.
[WARN]  Run: sudo python3 scripts/usbmon-capture.py
[INFO]  Released interface 3

════════════════════════════════════════════════════
  828ES  (serial 0001f2fffe00a4df)
════════════════════════════════════════════════════
[INFO]  Found vendor bulk interface #5: EP_OUT=0x04  EP_IN=0x83
[OK]    Claimed interface 5

[INFO]  ── Trying: GET /datastore  (HTTP/1.0, no framing)
[INFO]     Sending 52 bytes →
   b'GET /datastore HTTP/1.0\r\nHost: motu\r\nAccept: */*\r\n\r\n'
[INFO]     Wrote 52 bytes
[WARN]     No response received within timeout

[INFO]  ── Trying: GET /  (HTTP/1.0, no framing)
[INFO]     Sending 43 bytes →
   b'GET / HTTP/1.0\r\nHost: motu\r\nAccept: */*\r\n\r\n'
[INFO]     Wrote 43 bytes
[WARN]     No response received within timeout

[INFO]  ── Trying: GET /datastore  (HTTP/1.1)
[INFO]     Sending 71 bytes →
   b'GET /datastore HTTP/1.1\r\nHost: motu\r\nAccept: */*\r\nConnection: close\r\n\r\n'
[INFO]     Wrote 71 bytes
[WARN]     No response received within timeout

[WARN]  No HTTP response from any request variant.
[WARN]  Next step: capture USB traffic with usbmon while the Windows VM accesses the web UI.
[WARN]  Run: sudo python3 scripts/usbmon-capture.py
[INFO]  Released interface 5
```

If that gets a response, we're done — raw HTTP over bulk works and we can build the client directly. If it times out:

## Step 2 — capture Windows VM traffic to decode the framing
```
sudo modprobe usbmon
sudo python3 /home/simukka/src/motu-connect/scripts/usbmon-capture.py
```
(then access the MOTU web UI from the Windows VM while this runs)

Windows 10 VM (using virtualbox) with the MOTU drivers installed.
Connect the MOTU828es via the USB

A single request to `http://localhost:1280/0001f2fffe00a4df/datastore?client=812436393`

HAR object
```
{
  "log": {
    "version": "1.2",
    "creator": {
      "name": "WebInspector",
      "version": "537.36"
    },
    "pages": [
      {
        "startedDateTime": "2026-04-03T12:39:37.180Z",
        "id": "page_1",
        "title": "http://localhost:1280/0001f2fffe00a4df/datastore?client=812436393",
        "pageTimings": {
          "onContentLoad": 10126.670999999988,
          "onLoad": 10128.135999999984
        }
      }
    ],
    "entries": [
      {
        "_connectionId": "505",
        "_initiator": {
          "type": "other"
        },
        "_priority": "VeryHigh",
        "_resourceType": "document",
        "cache": {},
        "connection": "1280",
        "pageref": "page_1",
        "request": {
          "method": "GET",
          "url": "http://localhost:1280/0001f2fffe00a4df/datastore?client=812436393",
          "httpVersion": "HTTP/1.1",
          "headers": [
            {
              "name": "Accept",
              "value": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
            },
            {
              "name": "Accept-Encoding",
              "value": "gzip, deflate, br, zstd"
            },
            {
              "name": "Accept-Language",
              "value": "en-GB,en;q=0.9,en-US;q=0.8"
            },
            {
              "name": "Connection",
              "value": "keep-alive"
            },
            {
              "name": "Host",
              "value": "localhost:1280"
            },
            {
              "name": "If-None-Match",
              "value": "5964"
            },
            {
              "name": "Sec-Fetch-Dest",
              "value": "document"
            },
            {
              "name": "Sec-Fetch-Mode",
              "value": "navigate"
            },
            {
              "name": "Sec-Fetch-Site",
              "value": "none"
            },
            {
              "name": "Sec-Fetch-User",
              "value": "?1"
            },
            {
              "name": "Upgrade-Insecure-Requests",
              "value": "1"
            },
            {
              "name": "User-Agent",
              "value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0"
            },
            {
              "name": "sec-ch-ua",
              "value": "\"Chromium\";v=\"146\", \"Not-A.Brand\";v=\"24\", \"Microsoft Edge\";v=\"146\""
            },
            {
              "name": "sec-ch-ua-mobile",
              "value": "?0"
            },
            {
              "name": "sec-ch-ua-platform",
              "value": "\"Windows\""
            }
          ],
          "queryString": [
            {
              "name": "client",
              "value": "812436393"
            }
          ],
          "cookies": [],
          "headersSize": 753,
          "bodySize": 0
        },
        "response": {
          "status": 304,
          "statusText": "Not Modified",
          "httpVersion": "HTTP/1.1",
          "headers": [
            {
              "name": "Access-Control-Allow-Origin",
              "value": "*"
            },
            {
              "name": "Access-Control-Expose-Headers",
              "value": ""
            },
            {
              "name": "Cache-Control",
              "value": "no-cache"
            },
            {
              "name": "Date",
              "value": "Fri, 03 Apr 2026 12:40:09 GMT"
            },
            {
              "name": "Server",
              "value": "Microsoft-HTTPAPI/2.0"
            }
          ],
          "cookies": [],
          "content": {
            "size": 208693,
            "mimeType": "application/json"
          },
          "redirectURL": "",
          "headersSize": 174,
          "bodySize": 0,
          "_transferSize": 175,
          "_error": null,
          "_fetchedViaServiceWorker": false
        },
        "serverIPAddress": "[::1]",
        "startedDateTime": "2026-04-03T12:39:37.172Z",
        "time": 10132.873000000018,
        "timings": {
          "blocked": 53.73100000001844,
          "dns": -1,
          "ssl": -1,
          "connect": -1,
          "send": 0.18999999999999773,
          "wait": 10011.101999999977,
          "receive": 67.85000000002219,
          "_blocked_queueing": 8.278000000018437,
          "_workerStart": -1,
          "_workerReady": -1,
          "_workerFetchStart": -1,
          "_workerRespondWithSettled": -1
        }
      }
    ]
  }
}
```

It appears the Windows driver is proxying HTTP request from localhost:1280 to the USB device. 

From the HAR:

The MOTU Windows driver runs localhost:1280 as an HTTP proxy (Server: Microsoft-HTTPAPI/2.0)
URL format: http://localhost:1280/<serial>/datastore?client=<id> — the serial from the USB descriptor is the path component
ETag long-polling: If-None-Match: 5964 → waits ~10s → 304 Not Modified
From the USB capture, decoded byte-by-byte:

Every OUT packet first 4 bytes: [seq:u8] [flags:u8] [total_len:u16-LE]

flags 0x81 = ping, 0x80 = data request, 0x00 = device response
Every data packet inner frame (bytes 4–31):

[4-7] = message type ("NREK" or "PTTH")
[8-11] = session nonce
[12-15] = per-message-type counter (LE u32)
[16-19] = constant 0x00000001
[20-21] = 0x0000
[22-23] = payload length (total − 24)
[24-27] = "MOTU" magic
[28-31] = 0x08000000
[32…] = raw HTTP (for PTTH) or keepalive data (for NREK)

## NOTE
usbmon captures at the USB packet level (max 512 bytes per packet), not the USB bulk transfer level. 
The analyze-capture.py script treats each 512-byte JSONL line as an independent frame, but large responses 
are actually a single logical transfer — one outer+inner header in the first 512-byte URB, followed by 
raw body continuation in subsequent URBs with no repeated headers.

The read(EP_BULK_IN, 65536) via libusb operates at the transfer level and should receive complete frames.

# Wireshark USB Capture Guide

## Goal

The existing `capture-windows-boot.jsonl` was captured via usbmon's text interface, which truncates payloads to 32 bytes. We need full-payload captures to resolve the protocol gaps listed below.

## Protocol Gaps to Investigate

Each capture scenario below targets specific unknowns. When analysing, look for:

1. **Session ID lifecycle** — Is `session_id` random per-frame or stable per-session? Do IN responses echo the OUT request's session_id?
2. **CONNECT handshake details** — Does the device send anything beyond the 8-byte PONG after CONNECT? (capabilities, version, etc.)
3. **Chunked response mechanics** — What triggers chunk boundaries? Is it always 4096 bytes? Does `chunk_idx` increment? Must the host PING between every chunk?
4. **IN frame footer** — Is the 4-byte footer (outer header copy) present on ALL IN data frames, including small ones?
5. **Error responses** — What does the device send for invalid paths or malformed requests? Binary-encoded HTTP 4xx/5xx, or a protocol-level error frame?
6. **Sequence number strictness** — Does the device validate OUT seq numbers? Can we start at any value?
7. **NREK vs PTTH concurrency** — Can both channels be active simultaneously? Are session_ids and msg_seqs truly independent?
8. **Long-poll termination** — How does the NREK long-poll return? Binary-encoded 304 status, or something else?
9. **Payload_len field** — Does it always equal `total_len - 32`? Does it differ for continuation chunks?
10. **Device-initiated messages** — Can the device push data without a preceding request?

## Setup: Full-Payload Capture with tcpdump

### Prerequisites

```bash
# Load the usbmon kernel module
sudo modprobe usbmon

# Find the MOTU device bus number
lsusb | grep 07fd
# Example output: Bus 007 Device 011: ID 07fd:0005 Mark of the Unicorn
# The bus number here is 7
```

### Option A: tcpdump (recommended — simplest, produces pcap for Wireshark)

```bash
# Replace usbmon7 with your bus number from lsusb
sudo tcpdump -i usbmon7 -w captures/motu-$(date +%Y%m%d-%H%M%S).pcap -s 0

# -s 0 = capture full packets (no truncation)
# Press Ctrl+C to stop
```

Open the resulting .pcap in Wireshark. Filter to bulk transfers on the MOTU endpoints:
```
usb.endpoint_address == 0x04 || usb.endpoint_address == 0x83
```

### Option B: usbmon-capture.py with binary mode

The script already supports `/dev/usbmon<N>` binary capture (full payloads). If `/dev/usbmon<N>` doesn't exist:

```bash
# Find the major number and create the device node
MAJOR=$(grep usbmon /proc/devices | awk '{print $1}')
BUS=7  # your bus number
sudo mknod /dev/usbmon${BUS} c ${MAJOR} ${BUS}

# Then run the capture script
sudo python3 scripts/usbmon-capture.py
```

### Option C: Wireshark GUI directly

If Wireshark is installed with USBPcap support, you can capture interactively:
1. Open Wireshark
2. Select `usbmon7` (or your bus) as the capture interface
3. Start capture
4. Interact with the device
5. Stop capture and apply display filter: `usb.endpoint_address == 0x04 || usb.endpoint_address == 0x83`

## Capture Scenarios

Create a `captures/` directory and run each scenario as a separate capture file. On the host Linux machine, start `tcpdump` before each scenario, then perform the action in the Windows VM.

```bash
mkdir -p captures
```

### Scenario 1: Cold boot handshake

**What to capture**: The very first communication when the MOTU driver connects to the device.

**Procedure**:
1. Start tcpdump: `sudo tcpdump -i usbmon7 -w captures/01-cold-boot.pcap -s 0`
2. In the Windows VM, connect the MOTU 828ES USB (or restart the VM with the device attached)
3. Wait for the MOTU driver to initialise (the device LCD may update)
4. Wait 30 seconds after the driver settles
5. Stop tcpdump

**What to look for**:
- CONNECT frame and PONG response — is there anything beyond the 8-byte PONG?
- What are the first few OUT data frames? (driver likely sends POST /datastore/host/os, etc.)
- Initial seq and msg_seq values — do they always start at the same numbers?
- **Gap #2** (CONNECT details), **Gap #6** (sequence strictness)

### Scenario 2: Full GET /datastore (multi-chunk response)

**What to capture**: The initial datastore fetch which returns ~200 KB of JSON, delivered as multiple chunks.

**Procedure**:
1. Ensure the Windows VM is already connected to the MOTU device
2. Start tcpdump: `sudo tcpdump -i usbmon7 -w captures/02-get-datastore.pcap -s 0`
3. In the Windows VM, open Chrome and navigate to `http://localhost:1280/<serial>/datastore`
4. Wait for the page to fully load
5. Stop tcpdump

**What to look for**:
- The OUT NREK request frame — full payload to confirm our codec encoding
- The multi-chunk IN response: count the chunks, measure their sizes
- Does `chunk_idx` increment (0, 1, 2, …) on each IN frame?
- Does the host send PING between each chunk? Is there always exactly one PING per chunk?
- What is the exact chunk boundary size? 4096 bytes? 4068 bytes (4096 - 28 header)?
- The final short chunk — confirm this signals end-of-transfer
- The 4-byte footer on each IN data frame
- `session_id` — same value on all IN chunks, or different?
- **Gaps #1, #3, #4, #9**

### Scenario 3: Long-poll cycle (NREK with ETag)

**What to capture**: The NREK long-poll that the web UI uses to watch for datastore changes.

**Procedure**:
1. Start tcpdump: `sudo tcpdump -i usbmon7 -w captures/03-long-poll.pcap -s 0`
2. Open the MOTU web UI in the Windows VM (`http://localhost:1280/<serial>/`)
3. Wait 30-60 seconds without touching anything — the UI long-polls via NREK with `If-None-Match`
4. Then change a setting (e.g., turn a knob, change sample rate) so the poll returns data
5. Wait another 30 seconds
6. Stop tcpdump

**What to look for**:
- The NREK OUT request: does it include `If-None-Match` header with an ETag value?
- When nothing changes: does the device return a 304 response? What does 304 look like in the binary codec?
- When something changes: does it return 200 with the new datastore JSON?
- How long does the long-poll block before timing out on the device side?
- **Gap #8** (long-poll termination)

### Scenario 4: POST to change a setting

**What to capture**: A setting change via POST to confirm our request encoding.

**Procedure**:
1. Start tcpdump: `sudo tcpdump -i usbmon7 -w captures/04-post-setting.pcap -s 0`
2. In the MOTU web UI, change a simple setting:
   - Change the main output volume
   - Or change the sample rate (Mix > Routing > Sample Rate)
   - Or toggle phantom power on an input
3. Stop tcpdump

**What to look for**:
- The OUT PTTH frame with the POST request — compare byte-for-byte to our `encode_request()` output
- The IN PTTH response — status code, headers, body
- Does a 204 (No Content) response have a body? What about the footer?
- Does the device send an unsolicited NREK notification after the POST? (would answer Gap #10)
- **Gaps #4, #5, #10**

### Scenario 5: Concurrent PTTH + NREK

**What to capture**: Both channels active simultaneously.

**Procedure**:
1. Start tcpdump: `sudo tcpdump -i usbmon7 -w captures/05-concurrent.pcap -s 0`
2. Open the MOTU web UI (this starts NREK long-polling)
3. While the UI is open, rapidly change several settings in succession
4. Capture for 60 seconds
5. Stop tcpdump

**What to look for**:
- Are PTTH and NREK frames interleaved on the wire?
- Do they use different `session_id` values?
- Are `msg_seq` counters independent per channel?
- Does a PING/PONG exchange apply to one channel or both?
- **Gap #7** (channel concurrency)

### Scenario 6: Error cases

**What to capture**: Device responses to invalid or malformed requests.

**Procedure**:
1. Start tcpdump: `sudo tcpdump -i usbmon7 -w captures/06-errors.pcap -s 0`
2. In the Windows VM browser, navigate to `http://localhost:1280/<serial>/nonexistent/path`
3. Also try `http://localhost:1280/<serial>/datastore/invalid/deep/path`
4. Stop tcpdump

**What to look for**:
- Does the device return a 404 in the binary codec? What does the response frame look like?
- Are there any protocol-level error frames (special flag values, etc.)?
- **Gap #5** (error responses)

### Scenario 7: Reconnection

**What to capture**: Disconnecting and reconnecting to observe session reset.

**Procedure**:
1. Start tcpdump: `sudo tcpdump -i usbmon7 -w captures/07-reconnect.pcap -s 0`
2. With the MOTU web UI open, physically unplug the USB cable (or detach from VM)
3. Wait 5 seconds
4. Reconnect
5. Wait for the driver to re-establish the connection
6. Stop tcpdump

**What to look for**:
- Does the driver send a new CONNECT, or resume with the old session?
- Do sequence counters reset?
- **Gap #6** (sequence strictness)

### Scenario 8: Idle keepalive timing

**What to capture**: PING/PONG cadence when the connection is idle.

**Procedure**:
1. Start tcpdump: `sudo tcpdump -i usbmon7 -w captures/08-idle-keepalive.pcap -s 0`
2. Ensure the Windows VM has the MOTU device connected but no web UI open
3. Let it sit idle for 5 minutes
4. Stop tcpdump

**What to look for**:
- How frequently does the driver send PINGs? (interval in seconds)
- Are there any unsolicited IN data frames?
- Does the device ever initiate communication?
- **Gaps #6, #10**

## Analysis Workflow

After capturing, use `analyze-capture.py` extended for pcap input, or use Wireshark directly:

### In Wireshark

1. Open the pcap file
2. Apply display filter: `usb.endpoint_address == 0x04 || usb.endpoint_address == 0x83`
3. For each bulk transfer, examine the "Leftover Capture Data" field — this is the raw payload
4. First 4 bytes = outer header (seq, flags, total_len)
5. If flags == 0x82: CONNECT. If flags == 0x81: PING. If flags == 0x00 and len == 8: PONG.
6. If flags == 0x80 (OUT data) or 0x00 with len > 8 (IN data): decode inner header at bytes 4-31
7. Payload starts at byte 32

### Converting pcap to JSONL for analyze-capture.py

```bash
# Use tshark to extract bulk transfer data from pcap
tshark -r captures/02-get-datastore.pcap \
  -Y "usb.endpoint_address == 0x04 || usb.endpoint_address == 0x83" \
  -T json \
  -e usb.endpoint_address -e usb.data_len -e usb.capdata \
  > captures/02-get-datastore.json
```

Or write a converter script (TODO: `scripts/pcap-to-jsonl.py`).