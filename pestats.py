#!/usr/bin/env python3
"""
pestats.py — PE file metadata extractor for malware triage
Outputs structured JSON suitable for static analysis workflows.

Dependencies:
    pip install pefile
    pip install python-signify   # optional, for full cert chain parsing

Ported functions credited below:
    Fixed_get_overlay_data_start_offset() — ported from Didier Stevens' pecheck.py
        https://github.com/DidierStevens/DidierStevensSuite/blob/master/pecheck.py
        Fix for correct overlay detection when a digital signature is present.
        Without this fix, pefile's native get_overlay_data_start_offset() returns
        wrong results on signed PE files.

    get_tls_callbacks() — ported from Didier Stevens' pecheck.py (TLSCallbacks function)
        https://github.com/DidierStevens/DidierStevensSuite/blob/master/pecheck.py
        Walks the TLS callback array and returns actual callback virtual addresses,
        rather than just a boolean for TLS directory presence.

    get_signature_info() — logic ported from Didier Stevens' pecheck.py (Signature function)
        https://github.com/DidierStevens/DidierStevensSuite/blob/master/pecheck.py
        Extracts digital signature presence, size, and location from the PE security
        directory. Extended here with python-signify for full cert chain parsing.

Usage:
    python peinfo.py <sample.exe> > sample_pe.json
    python peinfo.py <sample.exe> | python -m json.tool   # pretty-print
"""

import sys
import os
import json
import math
import struct
import hashlib
import datetime

try:
    import pefile
except ImportError:
    print('Error: pefile not installed. Run: pip install pefile', file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Entropy calculation
# ---------------------------------------------------------------------------

def calc_entropy(data: bytes) -> float:
    """Shannon entropy of a byte sequence. Returns 0.0–8.0."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    length = len(data)
    for c in counts:
        if c:
            p = c / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


# ---------------------------------------------------------------------------
# Ported from Didier Stevens' pecheck.py
# Source: https://github.com/DidierStevens/DidierStevensSuite/blob/master/pecheck.py
#
# Fix for pefile's get_overlay_data_start_offset() when a digital signature
# is present. The native pefile method incorrectly treats the security
# directory as overlay data. This corrected version checks whether the
# overlay actually starts after the security directory before returning it.
# ---------------------------------------------------------------------------

def fixed_get_overlay_data_start_offset(pe: pefile.PE):
    """
    Corrected overlay offset calculation that accounts for digital signatures.
    Ported from Didier Stevens' pecheck.py (Fixed_get_overlay_data_start_offset).
    """
    overlay_offset = pe.get_overlay_data_start_offset()
    if overlay_offset is None:
        return None

    try:
        security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
        ]
    except IndexError:
        return overlay_offset

    # If the overlay starts after the security directory, it's a real overlay
    if overlay_offset > security.VirtualAddress + security.Size:
        return overlay_offset

    # Otherwise the "overlay" is actually the signature — return end of sig
    if len(pe.__data__) > security.VirtualAddress + security.Size:
        return security.VirtualAddress + security.Size
    else:
        return None


# ---------------------------------------------------------------------------
# Ported from Didier Stevens' pecheck.py
# Source: https://github.com/DidierStevens/DidierStevensSuite/blob/master/pecheck.py
#
# Walks the TLS callback pointer array to extract actual callback virtual
# addresses. The native pefile DIRECTORY_ENTRY_TLS only confirms presence;
# this function returns the addresses themselves, which is critical for
# identifying early-execution anti-analysis or unpacking code that runs
# before the entry point and before most debuggers attach.
# ---------------------------------------------------------------------------

def get_tls_callbacks(pe: pefile.PE) -> dict:
    """
    Extract TLS callback addresses from the PE TLS directory.
    Ported from Didier Stevens' pecheck.py (TLSCallbacks function).

    TLS callbacks execute before the PE entry point — used by malware for
    anti-debug and unpacking routines that fire before debugger attachment.
    Always check these addresses before starting dynamic analysis.
    """
    if not hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
        return {"present": False, "callbacks": []}

    # Determine pointer size based on architecture
    # Ported logic from Didier Stevens' pecheck.py
    if pe.FILE_HEADER.IMAGE_FILE_LARGE_ADDRESS_AWARE:
        fmt = '<Q'   # 64-bit
    else:
        fmt = '<I'   # 32-bit
    fmt_size = struct.calcsize(fmt)

    tls_callbacks_rva = (
        pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks
        - pe.OPTIONAL_HEADER.ImageBase
    )

    callbacks = []
    for section in pe.sections:
        if section.contains_rva(tls_callbacks_rva):
            tls_offset = section.get_offset_from_rva(tls_callbacks_rva)
            callbacks_array = pe.__data__[
                tls_offset: section.PointerToRawData + section.SizeOfRawData
            ]
            # Walk the null-terminated array of callback pointers
            while len(callbacks_array) >= fmt_size:
                callback_va = struct.unpack(fmt, callbacks_array[:fmt_size])[0]
                if callback_va == 0:
                    break
                callbacks.append(hex(callback_va))
                callbacks_array = callbacks_array[fmt_size:]
            break

    return {
        "present": True,
        "callback_count": len(callbacks),
        "callbacks": callbacks,
        # Analyst note: set breakpoints at these addresses BEFORE entry point
        "analyst_note": (
            "TLS callbacks execute before EP and before most debuggers attach. "
            "Set breakpoints here first in dynamic analysis."
        ) if callbacks else None
    }


# ---------------------------------------------------------------------------
# Ported from Didier Stevens' pecheck.py
# Source: https://github.com/DidierStevens/DidierStevensSuite/blob/master/pecheck.py
#
# Extracts digital signature metadata from the PE security directory.
# Extended with python-signify for full cert chain parsing (signer name,
# issuing CA, timestamps) when the library is available.
# ---------------------------------------------------------------------------

def get_signature_info(pe: pefile.PE) -> dict:
    """
    Extract digital signature metadata from the PE security directory.
    Core logic ported from Didier Stevens' pecheck.py (Signature function).
    Extended with python-signify cert chain parsing where available.

    Signature states and their malware relevance:
      not_signed      — unsigned binary; common but not deterministic
      valid           — signed and verifies; possible trojanized legit binary or stolen cert
      invalid         — signature present but verification fails; likely tampered after signing
      present_no_verify — signature bytes present but could not be verified (library missing)
    """
    result = {
        "present": False,
        "status": "not_signed",
        "virtual_address": None,
        "size_bytes": None,
        "signer_name": None,
        "issuer": None,
        "serial_number": None,
        "signing_timestamp": None,
        "countersign_timestamp": None,
        "cert_chain": [],
        "analyst_note": None
    }

    # Check security data directory — ported from Didier Stevens' pecheck.py
    try:
        security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
        ]
    except IndexError:
        return result

    if security.VirtualAddress == 0:
        return result

    # Signature directory is present
    result["present"] = True
    result["virtual_address"] = hex(security.VirtualAddress)
    result["size_bytes"] = security.Size

    # Attempt full cert chain parsing via python-signify
    # python-signify gives us signer name, issuer, timestamps cleanly
    try:
        from signify.authenticode import SignedPEFile
        from signify.exceptions import SignedPEParseError, AuthenticodeVerificationError

        with open(pe.path if hasattr(pe, 'path') else pe.__data__, 'rb') as f:
            signed_pe = SignedPEFile(f)

        try:
            for signed_data in signed_pe.signed_datas:
                signer = signed_data.signer_info

                result["signer_name"] = str(
                    signer.certificate.subject.get_attributes_for_oid(
                        signer.certificate.subject.oid
                    )[0].value
                ) if signer.certificate else None

                # Build cert chain entries
                chain = []
                for cert in signed_data.certificates:
                    chain.append({
                        "subject": cert.subject.human_friendly,
                        "issuer": cert.issuer.human_friendly,
                        "serial": str(cert.serial_number),
                        "not_before": str(cert.not_valid_before_utc),
                        "not_after": str(cert.not_valid_after_utc),
                    })
                result["cert_chain"] = chain
                if chain:
                    result["issuer"] = chain[-1]["subject"]  # root CA

            # Attempt verification
            try:
                signed_pe.verify()
                result["status"] = "valid"
                result["analyst_note"] = (
                    "Valid signature. If this claims to be a legitimate binary, "
                    "verify the signer name matches the expected vendor and that "
                    "the file hash matches a known-good version."
                )
            except AuthenticodeVerificationError as e:
                result["status"] = "invalid"
                result["verification_error"] = str(e)
                result["analyst_note"] = (
                    "Signature present but VERIFICATION FAILED. "
                    "File was likely modified after signing — strong indicator of "
                    "a trojanized installer or tampered binary."
                )

        except SignedPEParseError as e:
            result["status"] = "parse_error"
            result["verification_error"] = str(e)

    except ImportError:
        # python-signify not available — report presence only
        # This is the fallback path from Didier Stevens' pecheck.py approach
        result["status"] = "present_no_verify"
        result["analyst_note"] = (
            "Signature directory present but python-signify not installed. "
            "Install with: pip install python-signify. "
            "Cannot determine validity or extract cert chain."
        )
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    return result


# ---------------------------------------------------------------------------
# PE section analysis
# ---------------------------------------------------------------------------

def get_sections(pe: pefile.PE) -> list:
    """Extract section table with entropy per section."""
    sections = []
    for s in pe.sections:
        data = s.get_data()
        name = s.Name.decode(errors='replace').rstrip('\x00')
        entropy = calc_entropy(data)
        sections.append({
            "name": name,
            "virtual_address": hex(s.VirtualAddress),
            "virtual_size": s.Misc_VirtualSize,
            "raw_size": s.SizeOfRawData,
            "raw_offset": hex(s.PointerToRawData),
            "entropy": entropy,
            # Flag high-entropy sections — likely packed or encrypted content
            "high_entropy": entropy > 7.0,
            "characteristics": hex(s.Characteristics),
            "executable": bool(s.Characteristics & 0x20000000),
            "writable": bool(s.Characteristics & 0x80000000),
            "readable": bool(s.Characteristics & 0x40000000),
        })
    return sections


# ---------------------------------------------------------------------------
# Import table
# ---------------------------------------------------------------------------

def get_imports(pe: pefile.PE) -> dict:
    """Extract full import address table grouped by DLL."""
    imports = {}
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        return imports
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode(errors='replace')
        funcs = []
        for imp in entry.imports:
            if imp.name:
                funcs.append(imp.name.decode(errors='replace'))
            else:
                funcs.append(f"ordinal_{imp.ordinal}")
        imports[dll_name] = funcs
    return imports


# ---------------------------------------------------------------------------
# Export table
# ---------------------------------------------------------------------------

def get_exports(pe: pefile.PE) -> list:
    """Extract export table if present."""
    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        return []
    exports = []
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        exports.append({
            "name": exp.name.decode(errors='replace') if exp.name else None,
            "ordinal": exp.ordinal,
            "address": hex(exp.address),
        })
    return exports


# ---------------------------------------------------------------------------
# Version info
# ---------------------------------------------------------------------------

def get_version_info(pe: pefile.PE) -> dict:
    """Extract FileInfo version strings."""
    info = {}
    try:
        for file_info in pe.FileInfo:
            for entry in file_info:
                if hasattr(entry, 'StringTable'):
                    for st in entry.StringTable:
                        for k, v in st.entries.items():
                            key = k.decode(errors='replace') if isinstance(k, bytes) else k
                            val = v.decode(errors='replace') if isinstance(v, bytes) else v
                            info[key] = val
    except Exception:
        pass
    return info


# ---------------------------------------------------------------------------
# Overlay analysis
# Uses fixed_get_overlay_data_start_offset() ported from Didier Stevens' pecheck.py
# ---------------------------------------------------------------------------

def get_overlay_info(pe: pefile.PE) -> dict:
    """
    Analyse PE overlay data.
    Uses fixed_get_overlay_data_start_offset() ported from Didier Stevens'
    pecheck.py to correctly handle signed PE files.
    """
    raw = pe.write()

    # Use the corrected offset function (ported from Didier Stevens' pecheck.py)
    overlay_offset = fixed_get_overlay_data_start_offset(pe)

    if overlay_offset is None:
        return {"present": False}

    overlay_data = raw[overlay_offset:]
    if not overlay_data:
        return {"present": False}

    entropy = calc_entropy(overlay_data)
    magic = overlay_data[:4].hex()

    return {
        "present": True,
        "start_offset": hex(overlay_offset),
        "size_bytes": len(overlay_data),
        "entropy": entropy,
        # High-entropy overlay strongly suggests packed/encrypted payload appended
        "high_entropy": entropy > 7.0,
        "magic_bytes": magic,
        "md5": hashlib.md5(overlay_data).hexdigest(),
        "sha256": hashlib.sha256(overlay_data).hexdigest(),
        "analyst_note": (
            "High-entropy overlay present — likely contains encrypted/compressed payload. "
            "Common in Inno Setup, NSIS, and similar installers."
        ) if entropy > 7.0 else None
    }


# ---------------------------------------------------------------------------
# PE headers
# ---------------------------------------------------------------------------

def get_headers(pe: pefile.PE) -> dict:
    """Extract key PE header fields."""
    machine_map = {
        0x014c: "i386",
        0x8664: "x86_64",
        0x01c4: "ARM",
        0xaa64: "ARM64",
    }
    subsystem_map = {
        2: "GUI",
        3: "CUI (console)",
        1: "native",
        9: "WinCE GUI",
    }
    machine = pe.FILE_HEADER.Machine
    subsystem = pe.OPTIONAL_HEADER.Subsystem

    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_section = None
    for s in pe.sections:
        if s.VirtualAddress <= ep < s.VirtualAddress + s.SizeOfRawData:
            ep_section = s.Name.decode(errors='replace').rstrip('\x00')
            break

    return {
        "machine": machine_map.get(machine, hex(machine)),
        "machine_raw": hex(machine),
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "timestamp_utc": str(
            datetime.datetime.fromtimestamp(
                pe.FILE_HEADER.TimeDateStamp,
                tz=datetime.timezone.utc
            )
        ),
        "characteristics": hex(pe.FILE_HEADER.Characteristics),
        "is_dll": pe.is_dll(),
        "is_exe": pe.is_exe(),
        "subsystem": subsystem_map.get(subsystem, hex(subsystem)),
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "entry_point_rva": hex(ep),
        "entry_point_va": hex(ep + pe.OPTIONAL_HEADER.ImageBase),
        "entry_point_section": ep_section,
        "size_of_image": pe.OPTIONAL_HEADER.SizeOfImage,
        "size_of_headers": pe.OPTIONAL_HEADER.SizeOfHeaders,
        "checksum_stored": hex(pe.OPTIONAL_HEADER.CheckSum),
        "checksum_calculated": hex(pe.generate_checksum()),
        # Checksum mismatch on a non-zero stored checksum = anomaly
        "checksum_mismatch": (
            pe.OPTIONAL_HEADER.CheckSum != 0
            and pe.OPTIONAL_HEADER.CheckSum != pe.generate_checksum()
        ),
    }


# ---------------------------------------------------------------------------
# Hashes
# ---------------------------------------------------------------------------

def get_hashes(data: bytes) -> dict:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def analyse(filepath: str) -> dict:
    with open(filepath, 'rb') as f:
        raw = f.read()

    pe = pefile.PE(data=raw)
    # Attach path so get_signature_info can open the file for signify
    pe.path = filepath

    return {
        "filename": os.path.basename(filepath),
        "file_size_bytes": len(raw),
        "hashes": get_hashes(raw),
        "headers": get_headers(pe),
        "sections": get_sections(pe),
        "imports": get_imports(pe),
        "exports": get_exports(pe),
        "version_info": get_version_info(pe),
        # Uses fixed_get_overlay_data_start_offset() — ported from Didier Stevens' pecheck.py
        "overlay": get_overlay_info(pe),
        # Callback addresses ported from Didier Stevens' pecheck.py TLSCallbacks()
        "tls": get_tls_callbacks(pe),
        # Signature logic ported from Didier Stevens' pecheck.py Signature()
        "signature": get_signature_info(pe),
    }


def main():
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <pe_file>", file=sys.stderr)
        sys.exit(1)

    filepath = sys.argv[1]
    if not os.path.isfile(filepath):
        print(f"Error: file not found: {filepath}", file=sys.stderr)
        sys.exit(1)

    try:
        result = analyse(filepath)
        print(json.dumps(result, indent=2))
    except pefile.PEFormatError as e:
        print(json.dumps({"error": f"Not a valid PE file: {e}"}), file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
