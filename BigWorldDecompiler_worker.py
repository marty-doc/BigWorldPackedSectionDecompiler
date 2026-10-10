# -*- coding: utf-8 -*-
from __future__ import print_function

import argparse
import base64
import io
import os
import struct
import sys
import threading
import traceback
import time
import tempfile
import xml.etree.ElementTree as ET

# Log file is always placed next to this Python script.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(SCRIPT_DIR, "BigWorldDecompiler_log.txt")


try:
    text_type = unicode
except NameError:
    text_type = str


def log_text(value):
    """Convert log values to Unicode without failing on non-ASCII paths."""
    if isinstance(value, text_type):
        return value
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", "replace")
        except Exception:
            return text_type(value)
    try:
        return text_type(value)
    except Exception:
        return u"<unprintable log message>"


class AppLogger(object):
    def __init__(self, filename):
        self.filename = os.path.abspath(filename)
        self.lock = threading.RLock()

    def write(self, message):
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        line = u"[%s] %s\n" % (stamp, log_text(message))
        try:
            with self.lock:
                with io.open(
                    self.filename,
                    "a",
                    encoding="utf-8",
                    newline="\n"
                ) as f:
                    f.write(line)
        except Exception:
            # Do not silently discard logging failures: expose them on stderr.
            try:
                error = traceback.format_exc()
                sys.stderr.write("LOG WRITE FAILED (%s):\n%s\n" %
                                 (self.filename, error))
                sys.stderr.flush()
            except Exception:
                pass

    def exception(self, prefix="Unhandled exception"):
        self.write(prefix)
        try:
            tb = traceback.format_exc()
            for line in tb.rstrip().splitlines():
                self.write(line)
        except Exception:
            pass


LOGGER = AppLogger(LOG_FILE)


def log(message):
    """Keep worker logs concise; detailed successes remain disabled."""
    return


MAGIC = 0x62A14E45

SECTION = 0
STRING = 1
INT = 2
FLOAT = 3
BOOL = 4
BLOB = 5
ENCRYPTED_BLOB = 6


def byte_value(x):
    return x if isinstance(x, int) else ord(x)


def hx(x):
    return x.encode("hex") if hasattr(x, "encode") else x.hex()


def load_strings(data, pos):
    result = []
    while True:
        end = data.find(b"\x00", pos)
        if end < 0:
            raise ValueError("unterminated string table")
        raw = data[pos:end]
        pos = end + 1
        if raw == b"":
            return result, pos
        result.append(raw.decode("utf-8", "strict"))


def read_header(data, off, strings):
    if off + 2 > len(data):
        raise ValueError("truncated section header at 0x%X" % off)

    count = struct.unpack_from("<H", data, off)[0]
    records_off = off + 2
    data_base = off + 2 + count * 6 + 4

    if data_base > len(data):
        raise ValueError("section header exceeds file")

    records = []
    for i in range(count + 1):
        p = records_off + i * 6

        # Actual node records are 6 bytes (4-byte position + 2-byte key).
        # The final sentinel record contains only the 4-byte position.
        record_size = 6 if i < count else 4
        if p + record_size > len(data):
            raise ValueError("truncated section records at 0x%X" % p)

        packed = struct.unpack_from("<I", data, p)[0]
        pos = packed & 0x0FFFFFFF
        typ = (packed >> 28) & 0x0F

        key = None
        if i < count:
            key = struct.unpack_from("<H", data, p + 4)[0]
            if key >= len(strings):
                raise ValueError("invalid string index %d" % key)

        records.append((pos, typ, key))

    return count, records, data_base


def decode(raw, typ):
    if typ == STRING:
        # Never silently replace invalid bytes: that would destroy source data.
        # A strict error aborts before the original file is replaced.
        return raw.decode("utf-8", "strict")

    if typ == INT:
        if len(raw) == 0:
            return "0"
        if len(raw) == 1:
            return str(struct.unpack("<b", raw)[0])
        if len(raw) == 2:
            return str(struct.unpack("<h", raw)[0])
        if len(raw) == 4:
            return str(struct.unpack("<i", raw)[0])
        return "0x" + hx(raw)

    if typ == FLOAT:
        if not raw:
            return "0.0"
        if len(raw) % 4:
            return "0x" + hx(raw)
        n = len(raw) // 4
        return " ".join(
            "%.9g" % v for v in struct.unpack("<" + "f" * n, raw)
        )

    if typ == BOOL:
        return "true" if raw else "false"

    if typ == BLOB:
        return base64.b64encode(raw).decode("ascii")

    if typ == ENCRYPTED_BLOB:
        if not raw:
            return ""
        mode = byte_value(raw[0])
        payload = raw[1:]
        if mode == 1:
            decoded_bytes = [byte_value(c) ^ 0x9C for c in payload]
            if sys.version_info[0] < 3:
                # In Python 2.7, bytes is an alias for str and does not
                # construct a byte string from an integer generator.
                payload = "".join(chr(value) for value in decoded_bytes)
            else:
                payload = bytes(bytearray(decoded_bytes))
        return base64.b64encode(payload).decode("ascii")

    raise ValueError("unknown type %d" % typ)


def parse_section(data, off, strings, depth=0, visited=None):
    if visited is None:
        visited = set()

    # Protect against malformed PackedSection data causing infinite recursion.
    if depth > 1000:
        raise ValueError(
            "maximum section nesting depth exceeded at 0x%X" % off
        )

    if off in visited:
        raise ValueError(
            "recursive section reference detected at 0x%X" % off
        )

    visited.add(off)

    count, records, base = read_header(data, off, strings)
    log(
        "SECTION: depth=%d offset=0x%X count=%d data_base=0x%X" %
        (depth, off, count, base)
    )
    result = []

    for i in range(count):
        start = records[i][0]
        end = records[i + 1][0]
        typ = records[i + 1][1]
        name = strings[records[i][2]]

        if start > end:
            raise ValueError("invalid range for <%s>" % name)

        a = base + start
        b = base + end

        if b > len(data):
            raise ValueError(
                "data range outside file for <%s>" % name
            )

        raw = data[a:b]

        if i < 10 or i % 1000 == 0:
            log(
                ("  NODE: depth=%d index=%d/%d name=<%s> type=%d "
                 "range=0x%X-0x%X size=%d") %
                (depth, i + 1, count, name, typ, a, b, len(raw))
            )

        if typ == SECTION:
            value = parse_section(
                data, a, strings, depth + 1, visited
            )
        else:
            value = decode(raw, typ)

        result.append((name, typ, value))

    # Treat visited as the active recursion stack, not a global set. Repeated
    # references to the same section are valid; only actual cycles are errors.
    visited.remove(off)
    return result


def xml_escape(value):
    value = value.replace("&", "&amp;")
    value = value.replace("<", "&lt;")
    value = value.replace(">", "&gt;")
    value = value.replace('"', "&quot;")
    value = value.replace("'", "&apos;")
    return value


def safe_xml_name(name):
    # BigWorld keys normally already contain valid XML names.
    # Keep them unchanged whenever possible.
    if not name:
        return "_empty"

    first = name[0]
    if not (first.isalpha() or first == "_" or ord(first) >= 128):
        name = "_" + name

    result = []
    for ch in name:
        if (
            ch.isalnum()
            or ch in "._:-"
            or ord(ch) >= 128
        ):
            result.append(ch)
        else:
            result.append("_")

    return "".join(result)


def emit(nodes, level=1):
    out = []
    indent = "  " * level

    for name, typ, value in nodes:
        if name == "xmlns:xmlref":
            continue

        xml_name = safe_xml_name(name)

        if typ == SECTION:
            out.append("%s<%s>" % (indent, xml_name))
            out.extend(emit(value, level + 1))
            out.append("%s</%s>" % (indent, xml_name))
        else:
            out.append(
                "%s<%s>%s</%s>" %
                (indent, xml_name, xml_escape(value), xml_name)
            )

    return out


def decompile(src, dst):
    total_started = time.time()
    stages = {}
    log("DECOMPILE START: %s" % src)
    log("Reading input file: %s" % src)

    stage_started = time.time()
    with open(src, "rb") as f:
        data = f.read()
    stages["read"] = time.time() - stage_started

    log("Input read successfully: %d bytes" % len(data))

    # Already-decoded XML is not an error.  Leave it untouched and let the
    # worker report a successful skip instead of trying to parse it as binary.
    xml_probe = data.lstrip(b"\xef\xbb\xbf \t\r\n")
    if xml_probe.startswith(b"<"):
        log("SKIP: already plain XML: %s" % src)
        return {
            "skipped": True,
            "input_size": len(data)
        }

    if len(data) < 5:
        raise ValueError("file is too small")

    magic = struct.unpack_from("<I", data, 0)[0]
    log("Magic: 0x%08X" % magic)

    if magic != MAGIC:
        raise ValueError(
            "bad magic: 0x%08X (expected 0x%08X)" %
            (magic, MAGIC)
        )

    version = byte_value(data[4])
    log("PackedSection version: %d" % version)

    log("Reading string table...")
    stage_started = time.time()
    strings, root = load_strings(data, 5)
    stages["string_table"] = time.time() - stage_started
    log(
        "String table loaded: %d strings, root offset 0x%X" %
        (len(strings), root)
    )

    log("Parsing PackedSection tree...")
    stage_started = time.time()
    tree = parse_section(data, root, strings)
    stages["parse"] = time.time() - stage_started
    log("PackedSection tree parsed successfully")

    # Namespace declarations are stored by PackedSection as top-level keys
    # such as "xmlns:ussr". They must become attributes on the document root,
    # not child elements like <xmlns:ussr>, which XML rejects as an unbound
    # prefix. Preserve their values and emit the remaining nodes as children.
    # PackedSection can repeat namespace keys many times in the same root
    # section (especially in large customization lists). XML forbids duplicate
    # attributes, even when their values are identical, so keep one declaration
    # per namespace prefix while preserving the first-seen order.
    namespace_values = {}
    namespace_order = []
    child_nodes = []
    for name, typ, value in tree:
        if name.startswith("xmlns:") and typ != SECTION:
            if name not in namespace_values:
                namespace_values[name] = value
                namespace_order.append(name)
            elif namespace_values[name] != value:
                raise ValueError(
                    "conflicting namespace declaration %s: %r versus %r" %
                    (name, namespace_values[name], value)
                )
        else:
            child_nodes.append((name, typ, value))

    root_attrs = [
        '%s="%s"' % (name, xml_escape(namespace_values[name]))
        for name in namespace_order
    ]

    # Use the original filename as the document root. A dot in an XML
    # element name is legal, so names such as "vehicle_filters.xml" stay
    # unchanged. Do not add an XML declaration.
    root_name = safe_xml_name(os.path.basename(src))
    root_open = "<%s%s>" % (
        root_name,
        (" " + " ".join(root_attrs)) if root_attrs else ""
    )
    lines = [root_open]
    lines.extend(emit(child_nodes))
    lines.append("</%s>" % root_name)

    stage_started = time.time()
    xml = "\n".join(lines) + "\n"
    xml_bytes = xml.encode("utf-8")
    xml_size = len(xml_bytes)
    stages["xml_generation"] = time.time() - stage_started

    log("XML generated: %d bytes" % xml_size)
    log("Writing temporary XML: %s" % dst)

    stage_started = time.time()
    # Write bytes explicitly: this guarantees UTF-8 without a BOM and
    # guarantees that byte zero is the opening '<' of the document root.
    with open(dst, "wb") as f:
        f.write(xml.encode("utf-8"))
        f.flush()
        try:
            os.fsync(f.fileno())
        except (AttributeError, OSError):
            pass

    # Do not replace the original with malformed XML. ElementTree accepts
    # legal names such as "vehicle_filters.xml" and checks well-formedness.
    try:
        ET.parse(dst)
    except Exception as exc:
        raise ValueError("generated XML is not well-formed: %s" % exc)

    stages["write_validate"] = time.time() - stage_started
    stages["total_decompile"] = time.time() - total_started
    log("Temporary XML written and validated successfully: %s" % dst)
    log(
        "STAGE TIMES: read=%.3fs strings=%.3fs parse=%.3fs "
        "xml=%.3fs write+validate=%.3fs total=%.3fs" %
        (stages["read"], stages["string_table"], stages["parse"],
         stages["xml_generation"], stages["write_validate"],
         stages["total_decompile"])
    )

    return {
        "version": version,
        "strings": len(strings),
        "input_size": len(data),
        "output_size": xml_size,
        "stage_times": stages
    }


def _new_temp_path(directory, basename, suffix):
    """Create a unique temporary file in the destination directory."""
    fd, path = tempfile.mkstemp(
        prefix="." + basename + ".",
        suffix=suffix,
        dir=directory
    )
    os.close(fd)
    return path


def _replace_original(src, temp):
    """Replace src with temp, restoring original if rename fails."""
    directory = os.path.dirname(os.path.abspath(src))
    basename = os.path.basename(src)
    backup = _new_temp_path(directory, basename, ".bwbackup")
    os.remove(backup)  # Reserve a unique name, then let rename create it.
    moved_original = False

    try:
        os.rename(src, backup)
        moved_original = True
        try:
            os.rename(temp, src)
        except Exception:
            # Keep the original file safe even if the final rename fails.
            if (moved_original and not os.path.exists(src) and
                    os.path.exists(backup)):
                os.rename(backup, src)
                moved_original = False
            raise

        try:
            os.remove(backup)
            moved_original = False
            log("Temporary backup removed: %s" % backup)
        except Exception:
            # The new output is already in place. Log the cleanup problem;
            # the finally block makes another attempt.
            LOGGER.exception("Could not remove temporary backup: %s" % backup)
    finally:
        if os.path.exists(backup):
            try:
                if not os.path.exists(src):
                    os.rename(backup, src)
                else:
                    os.remove(backup)
            except Exception:
                LOGGER.exception("Backup cleanup/restore failed: %s" % backup)


def process_file(src):
    """Decode a file and replace it only after successful validation."""
    src = os.path.abspath(src)
    directory = os.path.dirname(src)
    basename = os.path.basename(src)
    temp = None

    process_started = time.time()
    log("PROCESS START: %s" % src)
    try:
        if not os.path.isfile(src):
            raise IOError("file not found: %s" % src)
        if not src.lower().endswith(".xml"):
            raise ValueError("worker accepts only .xml: %s" % src)

        temp = _new_temp_path(directory, basename, ".bwtmp")
        log("Temporary output file: %s" % temp)
        info = decompile(src, temp)

        if info.get("skipped"):
            log("PROCESS SKIPPED (already XML): %s" % src)
            return src, info

        replace_started = time.time()
        _replace_original(src, temp)
        info["replace_time"] = time.time() - replace_started
        temp = None  # It was renamed to src; do not try to delete it again.
        info["total_process_time"] = time.time() - process_started
        log("PROCESS SUCCESS: %s" % src)
        log("REPLACE TIME: %.3fs" % info["replace_time"])
        log("TOTAL FILE TIME: %.3fs" % info["total_process_time"])
        return src, info

    except Exception:
        # main_worker writes the single detailed traceback for this failure.
        raise

    finally:
        # Clean up per-file scratch files on success, skip, or failure.
        if temp and os.path.exists(temp):
            try:
                os.remove(temp)
                log("Temporary output removed: %s" % temp)
            except Exception:
                LOGGER.exception(
                    "Could not remove temporary output: %s" % temp
                )


def looks_like_candidate(filename):
    # We intentionally do not rely only on extension:
    # folder mode tries files and reports invalid PackedSection files.
    # folder mode tries files and simply reports invalid PackedSection files.
    return not filename.lower().endswith("_decompiled.xml")



def main_worker():
    parser = argparse.ArgumentParser(
        description="BigWorld PackedSection decompiler worker"
    )
    parser.add_argument("source")
    parser.add_argument(
        "--log-file",
        dest="log_file",
        default=LOG_FILE,
        help="Persistent log file path (normally supplied by the GUI)"
    )
    parsed = parser.parse_args()

    # Use the GUI's exact path so all subprocesses append errors to one log.
    LOGGER.filename = os.path.abspath(parsed.log_file)
    source = os.path.abspath(parsed.source)

    try:
        result_path, info = process_file(source)
        if info.get("skipped"):
            print("SKIP_ALREADY_XML")
            return 0

        return 0

    except BaseException:
        LOGGER.exception("WORKER EXCEPTION: %s" % source)
        # Also send the real exception to the parent GUI. This ensures the
        # cause remains visible even if persistent logging is unavailable.
        traceback.print_exc(file=sys.stderr)
        return 2


if __name__ == "__main__":
    try:
        sys.exit(main_worker())
    except Exception:
        LOGGER.exception("FATAL WORKER EXCEPTION")
        sys.exit(3)
