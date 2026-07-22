---
name: reenable-bridge-ssh
description: >-
  Re-enable SSH on the UniFi SuperLink bridge (USL Gateway) after it has been
  disabled by a factory reset, re-adoption, or firmware reprovision. Use this
  whenever `ssh ubnt@<bridge>` refuses/times out, whenever a bench step needs
  the bridge shell (keyhook/capture_key.sh, lorabrd restart, gdbserver) and SSH
  is off, or whenever the user says the bridge was reset / "re-enable ssh" /
  "the gateway lost ssh" / "turn ssh back on". The bridge drops the SSH flag on
  every reprovision, so this is a recurring need — reach for this skill instead
  of re-deriving the Protect API dance each time.
---

# Re-enable SSH on the SuperLink bridge

The USL Gateway (SuperLink bridge, the armv7l box running `lorabrd`) exposes SSH
only when Protect's per-device `isSshEnabled` flag is set. **Every bridge reset /
re-adoption / firmware reprovision clears it**, so after any of those, SSH stops
working and every bench step that needs the bridge shell is blocked.

The flag lives on Protect's **internal** API (`/proxy/protect/api/...`), which
requires a real logged-in session cookie + CSRF token. Shortcuts that DON'T work
(don't waste time on them):

- A Protect **Integration API key** (`X-API-KEY`, `/proxy/protect/integration/v1/...`)
  is read-only for this — it can list bridges but its PATCH schema rejects
  `isSshEnabled` ("must NOT have additional properties").
- **Root SSH on the console** alone does not get a Protect session — the internal
  `/api/` returns 401 to API-key, `Authorization: Bearer`, and even the
  `unifi-core-direct` mTLS client cert.

The reliable path is to ride the user's **already-authenticated browser session**.

## Procedure

### 1. Get a live Protect session in the browser

The console is the UCG-Fiber at `https://10.1.1.1/` (UniFi OS). Use the
`claude-in-chrome` tools. Navigate to the Network/Protect web UI. If you hit the
self-signed-cert "Privacy error" interstitial, the extension can't click through
it — ask the user to accept the cert once (they can do it in a second), then
proceed. Confirm you have a session by fetching the API from the page context.

### 2. Find the bridge and its current SSH state

Run in the page via `javascript_tool` (same-origin, cookies included). The
response headers carry the CSRF token you'll need for the writes:

```js
const r = await fetch('/proxy/protect/api/bridges', {credentials:'include'});
const csrf = r.headers.get('x-csrf-token');   // e.g. "f236...."
const b = (await r.json())[0];
({ id: b.id, host: b.host, mac: b.mac, isSshEnabled: b.isSshEnabled, csrf });
```

- `b.host` is the bridge's **current IP** — trust this over any hardcoded value.
  It drifts across resets (has been both `10.1.1.141` and `10.1.10.141`).
- `b.id` is the Protect bridge id (stable: `6a612ad103c80a03e4027261`, MAC
  `9041B23483DC`, name "USL Gateway").

### 3. Enable SSH on the bridge AND the NVR

Both must be set — the NVR-level flag gates propagation. PATCH the internal API
with the CSRF token in the `x-csrf-token` header:

```js
const CSRF = '<csrf-from-step-2>';
async function patch(path){
  const r = await fetch(path, {method:'PATCH', credentials:'include',
    headers:{'Content-Type':'application/json','x-csrf-token':CSRF},
    body: JSON.stringify({isSshEnabled:true})});
  return {path, status:r.status, isSshEnabled:(await r.json()).isSshEnabled};
}
[ await patch('/proxy/protect/api/bridges/6a612ad103c80a03e4027261'),
  await patch('/proxy/protect/api/nvr') ];
```

Expect `status:200, isSshEnabled:true` on both. **No device reboot is
required** — SSH comes up within a second or two.

### 4. Verify from the shell

SSH creds: user `ubnt`, password is the `webpass` baked into
`tools/keyhook/capture_key.sh` (currently
`zaLsHMDA7IdjmVhR1sFyODonQPfZ6h`). Use the IP from step 2 (`b.host`):

```bash
sshpass -p '<webpass>' ssh -o StrictHostKeyChecking=accept-new \
  ubnt@<bridge_host> 'echo SSH_OK; uname -a; pidof lorabrd && echo lorabrd_running'
```

A clean `SSH_OK` + `lorabrd_running` means done. If it still refuses after ~10 s,
re-check that step 3 returned 200 on **both** PATCHes, then as a fallback reboot
the bridge (`ssh ... 'reboot'` once it's reachable, or via the UI) and retry.

## Notes

- Console root (for other tasks) is `~/.ssh/config` host `router` (key auth),
  UCG-Fiber, UniFi OS. Not needed for this skill, but that's the box.
- If the browser session is unavailable and you only have the Integration API
  key, you can still *read* state (`GET /proxy/protect/integration/v1/bridges`)
  to confirm the bridge is `CONNECTED` and see its clients — but you cannot flip
  SSH from there.
- Full write-up with the dead-ends documented: `docs/gateway_ssh_access.md`.
