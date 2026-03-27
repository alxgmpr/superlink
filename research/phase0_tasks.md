# Phase 0: No-Device Research Tasks

## FCC Filings to Pull

Search https://apps.fcc.gov/oetcf/eas/reports/GenericSearch.cfm with grantee code **SWX**.

### Priority Devices (SuperLink-capable)
| Device | FCC ID | Status |
|--------|--------|--------|
| UDM-Pro | SWX-UDMPRO | TODO |
| UDM-SE | SWX-UDMSE | TODO |
| UDM-Pro Max | SWX-UDMPROMAX | TODO |
| UniFi Express | SWX-UX | TODO |
| UA-Hub | SWX-UAHUB | TODO |
| UA-Lite | SWX-UALITE | TODO |
| UA-Pro | SWX-UAPRO | TODO |
| USP-Plug | SWX-USPPLUG | TODO |
| USP-Strip | SWX-USPSTRIP | TODO |
| USP-PDU Pro | SWX-USPPDU | TODO |
| Connect Display | TBD | TODO |
| Building Bridge | TBD | TODO |

### What to Extract from Each Filing
- [ ] Internal photos (identify ICs, debug headers, antenna)
- [ ] Test setup photos (shows antenna configuration)
- [ ] RF test report (channel list, power levels, hopping pattern, dwell time)
- [ ] Block diagram (shows signal chain)
- [ ] Operational description (may describe protocol at high level)

## Firmware URLs to Try

Ubiquiti firmware is typically hosted at:
- `https://dl.ui.com/`
- `https://fw-download.ubnt.com/`
- Check the UniFi controller's firmware manifest for download URLs

## UniFi Controller Analysis

The UniFi Network Application can be downloaded from:
https://www.ui.com/download/releases/network-server

It's a Java application — key analysis targets:
- Decompile with `jadx` or `cfr`
- Search for: `superlink`, `lora`, `subghz`, `915`, `sx1262`, `sx1302`
- Look in the `inform` handler for SuperLink device types
- Check for protobuf/proto files defining message formats
