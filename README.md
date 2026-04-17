# pestats

# pestats.py

A PE file metadata extractor for malware triage. Parses Windows Portable Executable files and outputs structured JSON covering headers, sections, imports, exports, overlay data, TLS callbacks, digital signatures, and per-section entropy.

## Features

- **File hashes** — MD5, SHA-1, SHA-256
- **PE headers** — architecture, timestamps, entry point, image base, subsystem, checksum validation
- **Section table** — entropy per section, high-entropy flagging, RWX characteristics
- **Import / export tables** — full IAT grouped by DLL, export symbol list
- **Version info** — FileInfo string table extraction
- **Overlay analysis** — detects and hashes data appended after the PE structure; correctly handles signed PE files (see [Credits](#credits))
- **TLS callbacks** — extracts callback virtual addresses that execute *before* the entry point
- **Digital signature** — presence, size, and validity via `python-signify`; full cert chain including signer, issuer, serial, and timestamps when available

## Requirements

```
pip install pefile
pip install python-signify   # optional — required for signature verification and cert chain
```

Python 3.8+.

## Usage

```bash
python pestats.py <sample.exe>
python pestats.py <sample.exe> | python -m json.tool   # pretty-print
python pestats.py <sample.exe> > report.json           # save to file
```

## Output structure

```jsonc
{
  "filename": "sample.exe",
  "file_size_bytes": 1234567,
  "hashes": { "md5": "...", "sha1": "...", "sha256": "..." },
  "headers": {
    "machine": "x86_64",
    "timestamp_utc": "2023-01-15 10:22:00+00:00",
    "is_dll": false,
    "entry_point_rva": "0x1000",
    "entry_point_section": ".text",
    "checksum_mismatch": false,
    ...
  },
  "sections": [
    {
      "name": ".text",
      "entropy": 6.3421,
      "high_entropy": false,
      "executable": true,
      ...
    }
  ],
  "imports": {
    "KERNEL32.dll": ["CreateFileA", "VirtualAlloc", ...],
    ...
  },
  "exports": [],
  "version_info": { "ProductName": "...", "FileVersion": "..." },
  "overlay": {
    "present": true,
    "size_bytes": 98304,
    "entropy": 7.94,
    "high_entropy": true,
    "md5": "...",
    "sha256": "..."
  },
  "tls": {
    "present": true,
    "callback_count": 2,
    "callbacks": ["0x140001000", "0x140001080"]
  },
  "signature": {
    "present": true,
    "status": "valid",
    "signer_name": "...",
    "issuer": "...",
    "cert_chain": [...]
  }
}
```

## Analyst notes

**High-entropy sections** (`entropy > 7.0`) indicate packed or encrypted content. Common in UPX, custom packers, and shellcode loaders.

**TLS callbacks** execute before the PE entry point and before most debuggers attach. When present, set breakpoints at the reported callback addresses before starting dynamic analysis.

**Signature status values:**

| Status | Meaning |
|---|---|
| `not_signed` | No signature present |
| `valid` | Signature verifies successfully |
| `invalid` | Signature present but verification failed — likely tampered after signing |
| `present_no_verify` | Signature bytes present; `python-signify` not installed |
| `parse_error` | Signature could not be parsed |

A `checksum_mismatch` on a binary with a non-zero stored checksum is an anomaly worth investigating.

**Overlay data** is appended after the normal PE structure. High-entropy overlays are common in self-extracting installers (Inno Setup, NSIS) and droppers that store an encrypted second-stage payload.

## Credits

Three functions are ported from [Didier Stevens' pecheck.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pecheck.py):

| Function | Source | Purpose |
|---|---|---|
| `fixed_get_overlay_data_start_offset()` | `Fixed_get_overlay_data_start_offset` | Corrects pefile's native overlay detection, which gives wrong results on signed PE files by treating the security directory as overlay data |
| `get_tls_callbacks()` | `TLSCallbacks` | Walks the TLS callback pointer array to return actual callback VAs, not just a boolean for TLS directory presence |
| `get_signature_info()` | `Signature` | Extracts signature presence and location from the security data directory; extended here with `python-signify` for full cert chain parsing |

## License

MIT