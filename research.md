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