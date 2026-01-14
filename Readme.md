# Secure IoMT Attestation using TPM 2.0

A **technical implementation of hardware-rooted trust for IoMT devices** using **TPM 2.0**, **U-Boot–based boot measurement**, **remote attestation**, and **attestation-gated OTA updates** on a Raspberry Pi 4.

This repository focuses on **how trust is technically established and verified** across boot, runtime, and update phases, rather than high-level theory.

---

## Technical Problem

Most IoMT and embedded Linux devices:
- Boot without measuring firmware integrity
- Accept OTA updates without cryptographic attestation
- Lack hardware-protected key storage

As a result, **firmware tampering, persistent implants, and device impersonation** are trivial once software access is gained.

This project implements a **TPM-backed measured boot + remote attestation pipeline** that enforces:
- *"No attestation → no data → no update"*

---

## System Architecture (Implementation View)

```
┌──────────────┐
│ TPM 2.0      │  EK, AK, PCRs (0,7)
└─────┬────────┘
      │ SPI
┌─────▼────────┐
│ U-Boot       │  Measures kernel, dtb → PCR extend
└─────┬────────┘
      │
┌─────▼────────┐
│ Linux Kernel │
└─────┬────────┘
      │
┌─────▼────────┐
│ Flask TPM API│  /api/get_pcr_quote
└─────┬────────┘
      │ HTTP
┌─────▼────────┐
│ Verifier     │  Signature + PCR validation
└──────────────┘
```

---

## TPM & Bootloader Integration

### TPM Hardware
- **TPM:** Infineon SLB9670 (SPI)
- Enabled via Device Tree overlay:

```
dtparam=spi=on
dtoverlay=tpm-slb9670
```

### Why U-Boot
- Raspberry Pi first-stage bootloader is closed-source and unmeasurable
- U-Boot is used as a **measured second-stage bootloader**

### What Is Measured
During boot, U-Boot:
- Hashes kernel image (`kernel8.img`)
- Hashes DTB / initramfs (if present)
- Extends **PCR 0 and PCR 7** using SHA-256

This establishes a **static Root of Trust for Measurement (RTM)**.

Refer: https://github.com/joholl/rpi4-uboot-tpm

---

## TPM Provisioning

### Keys Used
- **Endorsement Key (EK):** TPM identity
- **Attestation Key (AK):** Signs PCR quotes

### Persistent AK Setup
```
tpm2_createek -c ek.ctx
tpm2_createak -C ek.ctx -c ak.ctx -u ak_pub.pem
tpm2_evictcontrol -C o -c ak.ctx 0x81000002
```

AK is persisted at handle `0x81000002` and used across reboots.

---

## Golden PCR Baseline

1. Perform a clean, trusted boot
2. Read PCR values:

```
tpm2_pcrread sha256:0,7
```

3. Store values as **golden reference** on verifier:

```json
{
  "0": "<sha256>",
  "7": "<sha256>"
}
```

All future boots are compared against this baseline.

---

## Remote Attestation Flow

### On Raspberry Pi

1. Generate PCR quote:
```
tpm2_quote -c 0x81000002 \
  -l sha256:0,7 \
  -m quote.msg \
  -s sig.dat
```

2. Read live PCRs:
```
tpm2_pcrread sha256:0,7
```

3. Return via REST API:
```json
{
  "pcr_values": {...},
  "quote": "base64(...)" ,
  "signature": "base64(...)"
}
```

### On Verifier

- Verify RSA signature using AK public key
- Compare PCR 0 and 7 against golden values

Trust decision is binary:
- **MATCH → trusted**
- **MISMATCH → compromised / modified**

---

## Attestation-Gated OTA Updates

OTA updates are done by using **private key authentication**.

Flow:
1. Verifier validates attestation
2. Only trusted devices receive update trigger
3. Device downloads firmware image
4. Optional re-attestation after reboot

This prevents:
- Malicious firmware injection
- Downgrade attacks
- Update abuse by compromised devices

---

## Runtime Deployment

### TPM API as Systemd Service

- Flask-based TPM API runs as a daemon
- Survives reboots and OTA updates
- Guarantees attestation availability

```
ExecStart=/usr/bin/python3 tpm_pi_server_new.py
Restart=always
User=root
```

---

## Security Guarantees Provided

| Threat | Mitigation |
|------|-----------|
| Firmware tampering | PCR mismatch detected |
| Device impersonation | TPM-backed AK identity |
| Rogue OTA updates | Attestation-gated updates |
| Persistent malware | Detected at boot |

---

## What This Project Demonstrates

- Practical TPM 2.0 usage (not simulation)
- Measured boot on embedded Linux
- Real remote attestation pipeline
- Secure firmware lifecycle control
- System-level security engineering

---

## Scope & Limitations

- Secure Boot (enforcement) is not enabled — this is **measured boot**
- First-stage Pi bootloader remains unmeasured
- OTA signature verification can be extended

---

## Author

**Cubher**  
Embedded & IoT Security | TPM | Firmware Attestation

---

⭐ Star the repo if you are interested in TPM-based embedded security

