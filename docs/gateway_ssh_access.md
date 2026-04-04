# Enabling SSH on Ubiquiti Protect Devices via Controller API

Ubiquiti Protect devices (USL-Gateway, cameras, etc.) don't expose SSH directly.
SSH must be enabled through the UniFi Protect controller API, then the device rebooted.

## Prerequisites

- UniFi Protect controller (e.g. Cloud Key, UDM, self-hosted) with admin access
- Device adopted into the controller
- Network access to both controller and device

## Step 1: Authenticate to the Controller

```bash
curl -k -c cookies.txt -D headers.txt \
  -X POST https://<CONTROLLER_IP>/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"<ADMIN_USER>","password":"<ADMIN_PASS>"}'
```

Extract the CSRF token from the response headers:
```bash
CSRF=$(grep -i 'x-updated-csrf-token' headers.txt | awk '{print $2}' | tr -d '\r')
```

## Step 2: Enable SSH on the Bridge (Device)

Find the bridge ID for your device. List all bridges:
```bash
curl -k -b cookies.txt \
  https://<CONTROLLER_IP>/proxy/protect/api/bridges
```

Enable SSH on the target bridge:
```bash
curl -k -b cookies.txt \
  -X PATCH https://<CONTROLLER_IP>/proxy/protect/api/bridges/<BRIDGE_ID> \
  -H 'Content-Type: application/json' \
  -H "x-csrf-token: $CSRF" \
  -d '{"isSshEnabled":true}'
```

## Step 3: Enable SSH on the NVR

The NVR also needs SSH enabled for the setting to propagate:
```bash
curl -k -b cookies.txt \
  -X PATCH https://<CONTROLLER_IP>/proxy/protect/api/nvr \
  -H 'Content-Type: application/json' \
  -H "x-csrf-token: $CSRF" \
  -d '{"isSshEnabled":true}'
```

## Step 4: Reboot the Device

The SSH setting takes effect after reboot. Trigger via the device's local web API:
```bash
curl -k https://<DEVICE_IP>/api/1.1/reboot
```

Wait ~60 seconds for reboot to complete.

## Step 5: SSH In

Default credentials are `ubnt` with the password shown in the device's local web UI
(accessible at `https://<DEVICE_IP>/` using the same admin credentials).

```bash
ssh ubnt@<DEVICE_IP>
```

## Notes

- The controller may **re-disable SSH on reprovisioning**. If SSH stops working after
  a firmware update or re-adoption, repeat the process.
- The local web UI at `https://<DEVICE_IP>/` uses its own credentials (username `ubnt`,
  password visible in the Protect controller under device settings).
- The CSRF token comes from the `x-updated-csrf-token` response header on login.
  It may also be refreshed on subsequent API responses — always use the latest one.
- The device's local API uses `/api/1.1/` (not `/api/1.0/`).
