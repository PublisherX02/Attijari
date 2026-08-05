"""Sandboxed archive/disk-image/LNK scanning.

Mirrors src/extraction.py's _local_archive_scan() logic exactly (that
function is also this container's EXTRACTION_ALLOW_UNSANDBOXED local
fallback) -- kept as a self-contained script, matching every other
scripts/*_scan.py in this directory, since the container has no access to
the rest of src/.

Contract: reports inspected=True only when the container was actually
opened and iterated. inspected=False must be treated by the caller as
suspicious/escalate -- "found nothing" and "couldn't look" must never
share a representation.
"""
import glob
import io
import json
import os
import sys
import zipfile

_DANGEROUS_ARCHIVE_MEMBER_EXTS = (".js", ".vbs", ".exe", ".scr", ".bat",
                                   ".ps1", ".hta", ".cmd", ".com", ".msi",
                                   ".jar", ".wsf", ".lnk")
_SCRIPT_EXTS = (".vbs", ".vbe", ".js", ".jse", ".wsf", ".ps1", ".hta")
_UNSUPPORTED_ARCHIVE_EXTS = (".rar", ".vhd", ".vhdx", ".cab")
_DISK_IMAGE_MIMES = {"application/x-iso9660-image", "application/x-cd-image", "application/x-raw-disk-image"}
_DISK_IMAGE_EXTS = (".iso", ".img")
_SEVENZIP_EXTS = (".7z",)
_MAX_NESTED_ARCHIVE_DEPTH = 3


def _local_yara(content: bytes) -> dict:
    try:
        import yara
    except ImportError:
        return {"suspicious": False, "matches": []}
    rule_files = glob.glob("/rules/*.yar") + glob.glob("/rules/*.yara")
    matches = []
    for rf in rule_files:
        try:
            rules = yara.compile(filepath=rf)
            for m in rules.match(data=content):
                matches.append({"rule": m.rule})
        except Exception:
            continue
    return {"suspicious": any("rule" in m for m in matches), "matches": matches}


def _detect_script_padding(content: bytes) -> str | None:
    if len(content) < 500_000:
        return None
    text = None
    for enc in ("utf-16-le", "utf-8", "latin-1"):
        try:
            candidate = content.decode(enc)
            printable_ratio = sum(1 for c in candidate[:2000] if c.isprintable() or c in "\r\n\t") / max(len(candidate[:2000]), 1)
            if printable_ratio > 0.9:
                text = candidate
                break
        except (UnicodeDecodeError, LookupError):
            continue
    if text is None:
        return None
    lines = text.splitlines()
    if len(lines) < 1000:
        return None
    unique_ratio = len(set(lines)) / len(lines)
    if unique_ratio < 0.05:
        return (f"script_padding_evasion: {len(content)} bytes, {len(lines)} lines, "
                f"only {unique_ratio:.1%} unique — repeated-junk padding, likely "
                f"defeating AV scan-size limits and plain-string signatures")
    return None


def _iter_iso_members(content: bytes, limit: int = 20, max_member_bytes: int = 10 * 1024 * 1024):
    try:
        import pycdlib
    except ImportError:
        return
    iso = pycdlib.PyCdlib()
    try:
        iso.open_fp(io.BytesIO(content))
    except Exception:
        return
    try:
        use_joliet = iso.has_joliet()
        walk_kwargs = {"joliet_path": "/"} if use_joliet else {"iso_path": "/"}
        yielded = 0
        for dirpath, _dirlist, filelist in iso.walk(**walk_kwargs):
            for fname in filelist:
                if yielded >= limit:
                    return
                full_path = f"{dirpath.rstrip('/')}/{fname}"
                try:
                    out = io.BytesIO()
                    if use_joliet:
                        iso.get_file_from_iso_fp(out, joliet_path=full_path)
                    else:
                        iso.get_file_from_iso_fp(out, iso_path=full_path)
                    data = out.getvalue()
                    if 0 < len(data) <= max_member_bytes:
                        yield fname.rstrip(";1"), data
                        yielded += 1
                except Exception:
                    continue
    except Exception:
        return
    finally:
        try:
            iso.close()
        except Exception:
            pass


def _iter_7z_members(content: bytes, limit: int = 20, max_member_bytes: int = 10 * 1024 * 1024):
    try:
        import py7zr
    except ImportError:
        return
    try:
        with py7zr.SevenZipFile(io.BytesIO(content), mode="r") as z:
            names = [n for n in z.getnames()][:limit]
            if not names:
                return
            extracted = z.read(targets=names)
            for name, stream in (extracted or {}).items():
                data = stream.read()
                if 0 < len(data) <= max_member_bytes:
                    yield name, data
    except Exception:
        return


def _extract_lnk_command(content: bytes) -> str | None:
    try:
        from LnkParse3.lnk_file import LnkFile
    except ImportError:
        return None
    try:
        lnk = LnkFile(indata=content)
        parsed = lnk.get_json(get_all=True)
    except Exception:
        return None
    if not isinstance(parsed, dict):
        return None
    parts = []
    data_section = parsed.get("data") or {}
    for key in ("command_line_arguments", "working_directory", "relative_path", "icon_location"):
        val = data_section.get(key)
        if val:
            parts.append(str(val))
    target = parsed.get("target") or {}
    for item in target.get("items", []) if isinstance(target, dict) else []:
        name = item.get("primary_name")
        if name:
            parts.append(str(name))
    return "\n".join(parts) if parts else None


def _scan_lnk_bytes(name: str, content: bytes, result: dict) -> None:
    lnk_text = _extract_lnk_command(content)
    if not lnk_text:
        return
    result["flags"].append(f"lnk_command ({name}): {lnk_text[:500]}")
    lnk_yara = _local_yara(lnk_text.encode("utf-8", errors="replace"))
    if lnk_yara.get("suspicious"):
        result["suspicious"] = True
        result["escalate"] = True
        matches = [m.get("rule", "?") for m in lnk_yara.get("matches", []) if "rule" in m]
        result["flags"].append(f"lnk_command_yara_match ({name}): {', '.join(matches)}")


def _scan_container_member(member_name: str, member_bytes: bytes, result: dict, depth: int = 0) -> None:
    """Applies every per-member check (YARA, dangerous extension, script
    padding, LNK command extraction) to one archive/disk-image member, and
    recurses into it if it is itself a nested archive/disk image -- up to
    _MAX_NESTED_ARCHIVE_DEPTH. Mutates `result` in place. Mirrors
    src/extraction.py's function of the same name exactly."""
    name_lower = member_name.lower()

    member_yara = _local_yara(member_bytes)
    if member_yara.get("suspicious"):
        result["suspicious"] = True
        result["escalate"] = True
        m_matches = [m.get("rule", "?") for m in member_yara.get("matches", []) if "rule" in m]
        result["flags"].append(
            f"archive_member_yara_match: {member_name} matched {', '.join(m_matches)}"
        )

    if any(name_lower.endswith(ext) for ext in _DANGEROUS_ARCHIVE_MEMBER_EXTS):
        result["suspicious"] = True
        result["escalate"] = True
        result["flags"].append(
            f"archive_dangerous_content: executable file inside archive: {member_name}"
        )

    if name_lower.endswith(_SCRIPT_EXTS):
        padding_flag = _detect_script_padding(member_bytes)
        if padding_flag:
            result["suspicious"] = True
            result["escalate"] = True
            result["flags"].append(f"{member_name}: {padding_flag}")

    if name_lower.endswith(".lnk"):
        _scan_lnk_bytes(member_name, member_bytes, result)

    if depth >= _MAX_NESTED_ARCHIVE_DEPTH:
        if name_lower.endswith(_DISK_IMAGE_EXTS + _SEVENZIP_EXTS + (".zip",)):
            result["suspicious"] = True
            result["escalate"] = True
            result["flags"].append(
                f"nested_archive_depth_exceeded: {member_name} not inspected "
                f"past depth {_MAX_NESTED_ARCHIVE_DEPTH}"
            )
        return

    try:
        if zipfile.is_zipfile(io.BytesIO(member_bytes)):
            with zipfile.ZipFile(io.BytesIO(member_bytes), "r") as inner_zf:
                for inner_member in inner_zf.infolist()[:20]:
                    if inner_member.file_size == 0 or inner_member.file_size > 10 * 1024 * 1024:
                        continue
                    try:
                        inner_bytes = inner_zf.read(inner_member.filename)
                    except RuntimeError:
                        continue
                    _scan_container_member(inner_member.filename, inner_bytes, result, depth + 1)
            return
    except Exception:
        pass

    if name_lower.endswith(_DISK_IMAGE_EXTS):
        try:
            for inner_name, inner_bytes in _iter_iso_members(member_bytes):
                _scan_container_member(inner_name, inner_bytes, result, depth + 1)
        except Exception:
            pass
        return

    if name_lower.endswith(_SEVENZIP_EXTS):
        try:
            for inner_name, inner_bytes in _iter_7z_members(member_bytes):
                _scan_container_member(inner_name, inner_bytes, result, depth + 1)
        except Exception:
            pass
        return


def scan(content: bytes, filename: str, effective_mime: str) -> dict:
    result = {
        "tool": "archive", "status": "ok", "format": "unknown",
        "inspected": False, "suspicious": False, "escalate": False, "flags": [],
    }
    fname_lower = filename.lower()

    if fname_lower.endswith(_UNSUPPORTED_ARCHIVE_EXTS):
        ext = next(e for e in _UNSUPPORTED_ARCHIVE_EXTS if fname_lower.endswith(e))
        result["format"] = ext.lstrip(".")
        result["suspicious"] = True
        result["escalate"] = True
        result["flags"].append(
            f"no_parser_available_for_format: {ext} attachments have no vetted "
            f"extraction library in this pipeline -- always escalated by design"
        )
        return result

    if fname_lower.endswith(".lnk"):
        result["format"] = "lnk"
        _scan_lnk_bytes(filename, content, result)
        result["inspected"] = True
        return result

    try:
        zf_buf = io.BytesIO(content)
        if zipfile.is_zipfile(zf_buf):
            result["format"] = "zip"
            zf_buf.seek(0)
            with zipfile.ZipFile(zf_buf, "r") as zf:
                total_compressed = sum(i.compress_size for i in zf.infolist() if i.compress_size > 0)
                total_decompressed = sum(i.file_size for i in zf.infolist())
                ratio = total_decompressed / total_compressed if total_compressed > 0 else 0

                nesting_depth = 0
                for member in zf.infolist():
                    if 0 < member.file_size <= 10 * 1024 * 1024:
                        try:
                            inner = zf.read(member.filename)
                            inner_buf = io.BytesIO(inner)
                            if zipfile.is_zipfile(inner_buf):
                                nesting_depth += 1
                                inner_buf.seek(0)
                                with zipfile.ZipFile(inner_buf, "r") as zf2:
                                    for m2 in zf2.infolist():
                                        if 0 < m2.file_size <= 10 * 1024 * 1024:
                                            try:
                                                inner2 = zf2.read(m2.filename)
                                                if zipfile.is_zipfile(io.BytesIO(inner2)):
                                                    nesting_depth += 1
                                                    break
                                            except Exception:
                                                pass
                                break
                        except Exception:
                            pass

                if nesting_depth >= 1 or ratio > 50:
                    result["suspicious"] = True
                    result["escalate"] = True
                    result["flags"].append(
                        f"archive_bomb_suspected: nesting_depth={nesting_depth} "
                        f"compression_ratio={ratio:.0f}x — possible zip bomb"
                    )

                for member in zf.infolist()[:20]:
                    if member.file_size == 0 or member.file_size > 10 * 1024 * 1024:
                        continue
                    try:
                        member_bytes = zf.read(member.filename)
                    except RuntimeError:
                        continue
                    _scan_container_member(member.filename, member_bytes, result, depth=1)
            result["inspected"] = True
            return result
    except Exception as e:
        result["flags"].append(f"archive_parse_error: {e}")
        result["suspicious"] = True
        result["escalate"] = True
        return result

    is_disk_image = (effective_mime in _DISK_IMAGE_MIMES or fname_lower.endswith(_DISK_IMAGE_EXTS))
    is_real_7z = (effective_mime == "application/x-7z-compressed" or fname_lower.endswith(_SEVENZIP_EXTS))
    if is_disk_image or is_real_7z:
        result["format"] = "iso" if is_disk_image else "7z"
        try:
            member_iter = _iter_iso_members(content) if is_disk_image else _iter_7z_members(content)
            for member_name, member_bytes in member_iter:
                _scan_container_member(member_name, member_bytes, result, depth=1)
            result["inspected"] = True
            return result
        except Exception as e:
            result["flags"].append(f"archive_parse_error: {e}")
            result["suspicious"] = True
            result["escalate"] = True
            return result

    result["flags"].append("archive_format_unrecognized_or_unsupported")
    result["suspicious"] = True
    result["escalate"] = True
    return result


if __name__ == "__main__":
    try:
        input_path = os.environ.get("ARCHIVE_SCAN_INPUT", "/work/input")
        content = open(input_path, "rb").read()
        filename = os.environ.get("ORIGINAL_NAME", "file.bin")
        effective_mime = os.environ.get("EFFECTIVE_MIME", "")
        result = scan(content, filename, effective_mime)
        json.dump(result, sys.stdout)
    except Exception as e:
        json.dump({"tool": "archive", "status": "error", "error": str(e),
                    "inspected": False, "suspicious": True, "escalate": True,
                    "flags": [f"archive_scan_crashed: {e}"]}, sys.stdout)
