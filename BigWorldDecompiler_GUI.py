# -*- coding: utf-8 -*-
from __future__ import print_function

import argparse
try:
    import Queue as queue
except ImportError:
    import queue
import base64
import io
import os
import re
import shutil
import struct
import subprocess
import sys
import threading
import time
import traceback
import zipfile

try:
    import Tkinter as tk
    import tkFileDialog
    import tkMessageBox
    import ttk
except ImportError:
    import tkinter as tk
    from tkinter import filedialog as tkFileDialog
    from tkinter import messagebox as tkMessageBox
    from tkinter import ttk


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
    """Persist lifecycle diagnostics without logging every successful file."""
    message = log_text(message)
    important = (
        message.startswith(("ERROR:", "FATAL", "TASK ERROR", "GUI START",
                            "TASK START", "FOLDER SCAN", "WORKER START",
                            "SUMMARY:", "LOG RESET", "CALLBACK ERROR"))
        or "EXCEPTION" in message
    )
    if important:
        LOGGER.write(message)


def clear_log_for_new_task():
    """Truncate the persistent log once, only when a new task starts."""
    # Open in write mode even if the file does not exist yet. If this fails,
    # let the GUI report it rather than silently running without a fresh log.
    with io.open(LOG_FILE, "w", encoding="utf-8", newline="\n") as f:
        f.write(u"")
    LOGGER.write("LOG RESET FOR NEW TASK: %s" % LOG_FILE)


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
        if p + 6 > len(data):
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
        return raw.decode("utf-8", "replace")

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
            payload = bytes(
                byte_value(c) ^ 0x9C for c in payload
            )
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
                "  NODE: depth=%d index=%d/%d name=<%s> "
                "type=%d range=0x%X-0x%X size=%d" %
                (depth, i + 1, count, name, typ, a, b, len(raw))
            )

        if typ == SECTION:
            value = parse_section(
                data, a, strings, depth + 1, visited
            )
        else:
            value = decode(raw, typ)

        result.append((name, typ, value))

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
    log("DECOMPILE START: %s" % src)
    log("Reading input file: %s" % src)

    with open(src, "rb") as f:
        data = f.read()

    log("Input read successfully: %d bytes" % len(data))

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
    strings, root = load_strings(data, 5)
    log(
        "String table loaded: %d strings, root offset 0x%X" %
        (len(strings), root)
    )

    log("Parsing PackedSection tree...")
    tree = parse_section(data, root, strings)
    log("PackedSection tree parsed successfully")

    # Use the original filename as the document root. A dot in an XML
    # element name is legal, so names such as "vehicle_filters.xml" stay
    # unchanged. Do not add an XML declaration.
    root_name = safe_xml_name(os.path.basename(src))
    lines = ["<%s>" % root_name]
    lines.extend(emit(tree))
    lines.append("</%s>" % root_name)

    xml = "\n".join(lines) + "\n"
    xml_size = len(xml.encode("utf-8"))

    log("XML generated: %d bytes" % xml_size)
    log("Writing temporary XML: %s" % dst)

    with io.open(dst, "w", encoding="utf-8", newline="\n") as f:
        f.write(xml)

    log("Temporary XML written successfully: %s" % dst)

    return {
        "version": version,
        "strings": len(strings),
        "input_size": len(data),
        "output_size": len(xml.encode("utf-8"))
    }


def get_worker_path():
    return os.path.join(
        SCRIPT_DIR,
        "BigWorldDecompiler_worker.py"
    )


def process_file(src):
    """Run the real parser in a separate Python process."""
    src = os.path.abspath(src)

    log("PROCESS START: %s" % src)
    log("Launching worker for: %s" % src)

    worker = get_worker_path()
    if not os.path.isfile(worker):
        raise IOError("Worker script not found: %s" % worker)

    # Pass the exact same log path to every subprocess. This avoids the GUI
    # and worker accidentally writing to different copies of the log.
    command = [
        sys.executable,
        worker,
        "--log-file",
        LOG_FILE,
        src
    ]

    log("Worker command: %s" % repr(command))

    creationflags = 0
    try:
        creationflags = subprocess.CREATE_NO_WINDOW
    except AttributeError:
        pass

    proc = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=creationflags
    )

    stdout_data, stderr_data = proc.communicate()

    if proc.returncode != 0:
        details = []
        if stdout_data:
            try:
                stdout_text = stdout_data.decode("utf-8", "replace")
            except AttributeError:
                stdout_text = stdout_data
            details.append("WORKER STDOUT:\n%s" % stdout_text)
        if stderr_data:
            try:
                stderr_text = stderr_data.decode("utf-8", "replace")
            except AttributeError:
                stderr_text = stderr_data
            details.append("WORKER STDERR / TRACEBACK:\n%s" % stderr_text)

        message = "Worker exit code %d: %s" % (proc.returncode, src)
        if details:
            message += "\n" + "\n".join(details)
        else:
            message += (
                "\nNo stdout/stderr was returned by the worker. "
                "Check %s" % LOG_FILE
            )
        raise RuntimeError(message)

    skipped = b"SKIP_ALREADY_XML" in (stdout_data or b"")
    # Worker already wrote the result and replaced the source file.
    return src, {"skipped": skipped}


def looks_like_candidate(filename):
    return filename.lower().endswith(".xml")


def next_xml_output_path():
    """Return the first unused XMLFILES<number> folder beside the GUI."""
    index = 1
    while True:
        candidate = os.path.join(SCRIPT_DIR, "XMLFILES%d" % index)
        if not os.path.exists(candidate):
            return candidate
        index += 1


def is_xml_output_folder(path):
    """Recognize output folders created by this GUI."""
    return (
        re.match(r"^XMLFILES[0-9]+$", os.path.basename(path), re.I)
        is not None
    )


def is_same_or_child_path(path, parent):
    """Path containment test that works with Python 2.7 and Windows paths."""
    path = os.path.normcase(os.path.abspath(path))
    parent = os.path.normcase(os.path.abspath(parent))
    return path == parent or path.startswith(parent.rstrip(os.sep) + os.sep)


def zip_member_to_unicode(name):
    """Decode ZIP member names while preserving non-ASCII names."""
    if isinstance(name, text_type):
        return name
    try:
        return name.decode("utf-8", "strict")
    except Exception:
        try:
            return name.decode("cp437", "strict")
        except Exception:
            return name.decode("utf-8", "replace")


def safe_archive_relative_path(name):
    """Normalize an archive path and reject absolute/traversal paths."""
    if not isinstance(name, text_type):
        name = zip_member_to_unicode(name)
    name = name.replace(u"\\", u"/")
    if not name or name.startswith(u"/"):
        return None
    # Reject drive-letter paths and any parent traversal segment.
    if re.match(r"^[A-Za-z]:", name):
        return None
    parts = name.split(u"/")
    if any(part in (u"", u".", u"..") for part in parts):
        return None
    return u"/".join(parts)


class DecompilerGUI(object):
    def __init__(self, root):
        self.root = root
        self.root.title("BigWorld PackedSection Decompiler")
        self.root.geometry("760x520")
        self.root.minsize(620, 420)

        self.busy = False
        self.files_total = 0
        self.files_done = 0
        self.files_ok = 0
        self.files_error = 0
        self.ui_queue = queue.Queue()
        self._closing = False

        self.build_ui()
        self.root.report_callback_exception = self.report_callback_exception
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(50, self._poll_ui_queue)
        self.log("Ready.")
        self.log("Log file: %s" % LOG_FILE)
        log("============================================================")
        log("BigWorld PackedSection Decompiler started")
        log("Log file: %s" % LOG_FILE)
        self.status("Ready")

    def build_ui(self):
        main = ttk.Frame(self.root, padding=12)
        main.pack(fill="both", expand=True)

        title = ttk.Label(
            main,
            text="BigWorld PackedSection Decompiler",
            font=("TkDefaultFont", 14, "bold")
        )
        title.pack(anchor="w", pady=(0, 10))

        buttons = ttk.Frame(main)
        buttons.pack(fill="x", pady=(0, 10))

        self.file_button = ttk.Button(
            buttons,
            text="Decompile XML file",
            command=self.choose_file
        )
        self.file_button.pack(side="left", padx=(0, 8))

        self.folder_button = ttk.Button(
            buttons,
            text="Decompile XML Folder",
            command=self.choose_folder
        )
        self.folder_button.pack(side="left", padx=(0, 8))

        self.get_xml_folder_button = ttk.Button(
            buttons,
            text="Get XML from folder",
            command=self.choose_xml_folder
        )
        self.get_xml_folder_button.pack(side="left", padx=(0, 8))

        self.get_xml_pkg_button = ttk.Button(
            buttons,
            text="Get XML from .PKG",
            command=self.choose_pkg_file
        )
        self.get_xml_pkg_button.pack(side="left", padx=(0, 8))

        self.clear_button = ttk.Button(
            buttons,
            text="Clear Log",
            command=self.clear_log
        )
        self.clear_button.pack(side="right")

        progress_frame = ttk.Frame(main)
        progress_frame.pack(fill="x", pady=(0, 8))

        self.progress = ttk.Progressbar(
            progress_frame,
            orient="horizontal",
            mode="determinate"
        )
        self.progress.pack(fill="x")

        self.status_var = tk.StringVar()
        self.status_label = ttk.Label(
            main,
            textvariable=self.status_var
        )
        self.status_label.pack(anchor="w", pady=(0, 6))

        log_frame = ttk.LabelFrame(main, text="Log", padding=6)
        log_frame.pack(fill="both", expand=True)

        self.log_text = tk.Text(
            log_frame,
            wrap="none",
            font=("Courier New", 9)
        )

        scroll_y = ttk.Scrollbar(
            log_frame,
            orient="vertical",
            command=self.log_text.yview
        )
        scroll_x = ttk.Scrollbar(
            log_frame,
            orient="horizontal",
            command=self.log_text.xview
        )

        self.log_text.configure(
            yscrollcommand=scroll_y.set,
            xscrollcommand=scroll_x.set
        )

        self.log_text.grid(row=0, column=0, sticky="nsew")
        scroll_y.grid(row=0, column=1, sticky="ns")
        scroll_x.grid(row=1, column=0, sticky="ew")

        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)

        bottom = ttk.Frame(main)
        bottom.pack(fill="x", pady=(8, 0))

        self.count_var = tk.StringVar()
        ttk.Label(
            bottom,
            textvariable=self.count_var
        ).pack(side="left")

    def safe_after(self, delay, callback):
        """Queue UI work for execution by Tk's main thread only."""
        try:
            self.ui_queue.put(callback)
        except Exception:
            pass

    def _poll_ui_queue(self):
        """Drain worker events without making Tk calls from worker threads."""
        if self._closing:
            return
        while True:
            try:
                callback = self.ui_queue.get_nowait()
            except queue.Empty:
                break
            try:
                callback()
            except Exception:
                LOGGER.exception("CALLBACK ERROR: queued UI callback failed")
        try:
            self.root.after(50, self._poll_ui_queue)
        except Exception:
            self._closing = True

    def on_close(self):
        """Avoid terminating while a worker may be replacing source files."""
        if self.busy:
            tkMessageBox.showwarning(
                "Operation in progress",
                "Please wait for the current operation to finish before closing."
            )
            return
        self._closing = True
        self.root.destroy()

    def report_callback_exception(self, exc_type, exc_value, exc_tb):
        """Record uncaught Tk callback exceptions."""
        try:
            detail = "".join(traceback.format_exception(
                exc_type, exc_value, exc_tb
            ))
            LOGGER.write("CALLBACK ERROR: uncaught Tkinter callback exception")
            for line in detail.rstrip().splitlines():
                LOGGER.write(line)
            self.status("GUI callback error; see log")
            try:
                tkMessageBox.showerror(
                    "BigWorld Decompiler - GUI error",
                    "A GUI action failed. Full details were saved to:\n%s" %
                    LOG_FILE
                )
            except Exception:
                pass
        except Exception:
            try:
                sys.stderr.write(traceback.format_exc())
            except Exception:
                pass

    def log(self, message):
        """Show errors and final summaries, not per-file successes or skips."""
        is_summary = message.startswith("SUMMARY:")
        is_error = message.startswith(("[ERROR]", "[TASK ERROR]", "ERROR:"))
        if not (is_summary or is_error):
            return
        if is_summary:
            LOGGER.write(message)

        def write():
            try:
                self.log_text.insert("end", message + "\n")
                self.log_text.see("end")
            except Exception:
                pass

        self.safe_after(0, write)

    def status(self, message):
        self.safe_after(
            0,
            lambda: self.status_var.set("Status: " + message)
        )

    def update_counts(self):
        text = (
            "Processed: %d    Success: %d    Skipped: %d    Errors: %d"
            % (
                self.files_done,
                self.files_ok,
                getattr(self, "files_skipped", 0),
                self.files_error
            )
        )
        self.safe_after(0, lambda: self.count_var.set(text))

    def set_busy(self, busy):
        self.busy = busy

        state = "disabled" if busy else "normal"

        self.safe_after(
            0,
            lambda: self.file_button.configure(state=state)
        )
        self.safe_after(
            0,
            lambda: self.folder_button.configure(state=state)
        )
        self.safe_after(
            0,
            lambda: self.get_xml_folder_button.configure(state=state)
        )
        self.safe_after(
            0,
            lambda: self.get_xml_pkg_button.configure(state=state)
        )

    def clear_log(self):
        if self.busy:
            return
        self.log_text.delete("1.0", "end")
        self.log("Log cleared.")
        self.status("Ready")

    def choose_file(self):
        if self.busy:
            return

        path = tkFileDialog.askopenfilename(
            title="Select BigWorld PackedSection file",
            initialdir=SCRIPT_DIR,
            filetypes=[
                ("XML files", "*.xml")
            ]
        )

        if not path:
            log("Compile File dialog cancelled")
            return

        LOGGER.write("TASK START: single file: %s" % path)
        self.log("Selected file: %s" % path)
        self.start_files([path])

    def choose_folder(self):
        """Scan recursively in a background thread, then decompile XML files."""
        if self.busy:
            return

        folder = tkFileDialog.askdirectory(
            title="Select folder to scan",
            initialdir=SCRIPT_DIR
        )
        if not folder:
            return

        try:
            clear_log_for_new_task()
            self.log_text.delete("1.0", "end")
        except Exception as error:
            tkMessageBox.showerror(
                "Log file error",
                "Cannot prepare log file:\n%s\n\n%s" % (LOG_FILE, error)
            )
            return

        folder = os.path.abspath(folder)
        LOGGER.write("TASK START: recursive decompile folder: %s" % folder)
        self.files_done = self.files_ok = self.files_error = 0
        self.files_skipped = 0
        self.set_busy(True)
        self.status("Scanning folders...")
        thread = threading.Thread(
            target=self._scan_folder_worker,
            args=(folder, "decompile")
        )
        thread.daemon = True
        thread.start()

    def _scan_folder_worker(self, folder, mode):
        """Build full paths off the UI thread; report traversal errors."""
        files = []
        scanned_dirs = 0
        scan_errors = []

        def walk_error(error):
            scan_errors.append(log_text(error))
            LOGGER.write("ERROR: Folder scan failed: %s" % error)

        try:
            for root_dir, dirs, names in os.walk(
                    folder, topdown=True, onerror=walk_error):
                scanned_dirs += 1
                dirs.sort()
                if mode == "copy":
                    # Skip only generated output folders directly beside this
                    # GUI; do not exclude unrelated user folders named XMLFILES1.
                    root_abs = os.path.normcase(os.path.abspath(root_dir))
                    gui_abs = os.path.normcase(os.path.abspath(SCRIPT_DIR))
                    if root_abs == gui_abs:
                        dirs[:] = [
                            d for d in dirs if not is_xml_output_folder(d)
                        ]
                for name in names:
                    if looks_like_candidate(name):
                        full_path = os.path.abspath(os.path.join(root_dir, name))
                        if mode == "decompile" and not name.lower().endswith(".xml"):
                            continue
                        if mode == "copy":
                            try:
                                relative_path = os.path.relpath(full_path, folder)
                                files.append((full_path, relative_path))
                            except Exception as error:
                                scan_errors.append(log_text(error))
                                LOGGER.write(
                                    "ERROR: Cannot calculate relative path for %s: %s" %
                                    (full_path, error)
                                )
                        else:
                            files.append(full_path)
            if mode == "copy":
                files.sort(key=lambda item: item[1].lower())
            else:
                files.sort()
            LOGGER.write(
                "FOLDER SCAN COMPLETE: mode=%s root=%s directories=%d files=%d errors=%d" %
                (mode, folder, scanned_dirs, len(files), len(scan_errors))
            )
            self.safe_after(0, lambda: self._finish_folder_scan(
                folder, mode, files, scanned_dirs, scan_errors))
        except Exception:
            LOGGER.exception("FATAL: recursive folder scan failed: %s" % folder)
            detail = traceback.format_exc()
            self.safe_after(0, lambda: self._finish_folder_scan(
                folder, mode, files, scanned_dirs, scan_errors, detail))

    def _finish_folder_scan(self, folder, mode, files, scanned_dirs,
                            scan_errors, fatal_error=None):
        """Continue a scan task on the Tk main thread."""
        if fatal_error:
            self.set_busy(False)
            self.status("Folder scan failed")
            tkMessageBox.showerror(
                "Folder scan error",
                "Could not scan the selected folder. Details were saved to:\n%s" % LOG_FILE
            )
            return
        if scan_errors:
            self.log("[ERROR] Folder scan completed with %d access/path error(s). See log." %
                     len(scan_errors))
        if not files:
            self.set_busy(False)
            self.status("No XML files found")
            tkMessageBox.showinfo(
                "BigWorld Decompiler",
                "No XML files found in the selected folder."
            )
            return
        if mode == "copy":
            self.set_busy(False)
            self.start_copy_task("folder", folder, files, reset_log=False)
        else:
            self.set_busy(False)
            self.start_files(files, reset_log=False)

    def choose_xml_folder(self):
        """Copy XML files from a folder tree, preserving relative paths."""
        if self.busy:
            return
        folder = tkFileDialog.askdirectory(
            title="Get XML from folder - Select folder",
            initialdir=SCRIPT_DIR
        )
        if not folder:
            return
        folder = os.path.abspath(folder)
        try:
            clear_log_for_new_task()
            self.log_text.delete("1.0", "end")
        except Exception as error:
            tkMessageBox.showerror(
                "Log file error",
                "Cannot prepare log file:\n%s\n\n%s" % (LOG_FILE, error)
            )
            return
        LOGGER.write("TASK START: copy XML folder: %s" % folder)
        self.files_done = self.files_ok = self.files_error = 0
        self.files_skipped = 0
        self.set_busy(True)
        self.status("Scanning folders...")
        thread = threading.Thread(
            target=self._scan_folder_worker,
            args=(folder, "copy")
        )
        thread.daemon = True
        thread.start()

    def choose_pkg_file(self):
        """Copy XML members from a ZIP-compatible BigWorld .pkg archive."""
        if self.busy:
            return

        path = tkFileDialog.askopenfilename(
            title="Get XML from .PKG - Select file",
            initialdir=SCRIPT_DIR,
            filetypes=[
                ("PKG files", "*.pkg"),
                ("All files", "*.*")
            ]
        )
        if not path:
            log("Get XML from .PKG dialog cancelled")
            return

        path = os.path.abspath(path)
        self.log("Get XML from .PKG: selected %s" % path)
        try:
            archive = zipfile.ZipFile(path, "r")
            try:
                entries = []
                skipped = 0
                for info in archive.infolist():
                    # ZipInfo.is_dir() is not available in every Python 2.7
                    # distribution; checking the trailing slash is compatible.
                    if (
                        info.filename.endswith("/")
                        or info.filename.endswith("\\")
                    ):
                        continue
                    member_name = zip_member_to_unicode(info.filename)
                    if not looks_like_candidate(member_name):
                        continue
                    rel = safe_archive_relative_path(member_name)
                    if rel is None:
                        skipped += 1
                        self.log(
                            "[SKIP] Unsafe archive path: %s" % member_name
                        )
                        continue
                    entries.append((info, rel))
            finally:
                archive.close()
        except Exception as e:
            LOGGER.write("ERROR: PKG archive open failed: %s" % e)
            tkMessageBox.showerror(
                "Get XML from .PKG",
                "Cannot read this file as a supported PKG/ZIP "
                "archive:\n%s\n\n%s" %
                (path, e)
            )
            return

        entries.sort(key=lambda item: item[1].lower())
        self.log("XML files found in PKG: %d" % len(entries))
        if skipped:
            self.log("Unsafe archive paths skipped: %d" % skipped)
        if not entries:
            tkMessageBox.showinfo(
                "Get XML from .PKG",
                "No XML files found in the selected archive."
            )
            return

        self.start_copy_task("pkg", path, entries)

    def start_copy_task(self, kind, source, entries, reset_log=True):
        """Start a copy-only task; the stable worker is not invoked."""
        if self.busy:
            return

        if reset_log:
            try:
                clear_log_for_new_task()
            except Exception as e:
                tkMessageBox.showerror(
                    "Log file error",
                    "Cannot reset log file:\n%s\n\n%s" % (LOG_FILE, e)
                )
                return
            self.log_text.delete("1.0", "end")

        try:
            # Recheck and create atomically to avoid collisions between instances.
            output_dir = next_xml_output_path()
            while True:
                try:
                    os.mkdir(output_dir)
                    break
                except OSError:
                    if os.path.exists(output_dir):
                        output_dir = next_xml_output_path()
                        continue
                    raise
        except Exception as e:
            LOGGER.exception("ERROR: Could not create XML output folder")
            tkMessageBox.showerror(
                "Output folder error",
                "Cannot create output folder:\n%s\n\n%s" %
                (locals().get("output_dir", SCRIPT_DIR), e)
            )
            return

        self.files_total = len(entries)
        self.files_done = 0
        self.files_ok = 0
        self.files_error = 0
        self.files_skipped = 0
        self.progress["maximum"] = max(1, self.files_total)
        self.progress["value"] = 0
        self.update_counts()
        self.set_busy(True)
        log("Copy task started: kind=%s source=%s output=%s" %
            (kind, source, output_dir))

        thread = threading.Thread(
            target=self.copy_worker,
            args=(kind, source, entries, output_dir)
        )
        thread.daemon = True
        thread.start()

    def copy_worker(self, kind, source, entries, output_dir):
        """Copy XML files byte-for-byte and preserve directory structure."""
        archive = None
        try:
            if kind == "pkg":
                archive = zipfile.ZipFile(source, "r")

            for index, entry in enumerate(entries):
                if kind == "folder":
                    src, relative_path = entry
                else:
                    info, relative_path = entry
                    src = "%s :: %s" % (source, relative_path)

                target = None
                target_created = False
                try:
                    relative_path = safe_archive_relative_path(relative_path)
                    if relative_path is None:
                        raise ValueError("unsafe relative path")
                    target = os.path.abspath(os.path.join(
                        output_dir, *relative_path.split("/")))
                    output_abs = os.path.abspath(output_dir)
                    if (
                        not is_same_or_child_path(target, output_abs)
                        or target == output_abs
                    ):
                        raise ValueError(
                            "destination path escapes output folder"
                        )
                    parent = os.path.dirname(target)
                    if not os.path.isdir(parent):
                        os.makedirs(parent)
                    if os.path.exists(target):
                        raise IOError(
                            "destination exists; duplicate archive path"
                        )

                    target_created = True
                    if kind == "folder":
                        shutil.copy2(entry[0], target)
                    else:
                        with archive.open(entry[0], "r") as src_stream:
                            with open(target, "wb") as dst_stream:
                                shutil.copyfileobj(src_stream, dst_stream)

                    self.files_ok += 1
                except Exception as e:
                    if target_created and target and os.path.isfile(target):
                        try:
                            os.remove(target)
                        except Exception:
                            LOGGER.exception(
                                "Could not remove partial copy: %s" % target
                            )
                    self.files_error += 1
                    self.log("[ERROR] %s: %s" % (src, e))
                    LOGGER.exception("Copy failed: %s" % src)

                self.files_done += 1
                self.update_counts()
                self.safe_after(
                    0,
                    lambda value=self.files_done:
                        self.progress.configure(value=value)
                )
        except Exception as e:
            self.files_error += 1
            self.log("[TASK ERROR] %s" % e)
            LOGGER.exception("Copy task failed")
        finally:
            if archive is not None:
                try:
                    archive.close()
                except Exception:
                    self.files_error += 1
                    LOGGER.exception("Could not close source archive")

        self.set_busy(False)
        if self.files_error:
            self.status("Copy finished with errors")
        else:
            self.status("Copy finished")
        self.log(
            "SUMMARY: Copy finished. Total=%d Success=%d Errors=%d "
            "Output=%s" %
            (self.files_total, self.files_ok, self.files_error, output_dir)
        )

    def start_files(self, files, reset_log=True):
        if self.busy:
            return

        # Clear once per task. Folder mode can clear before scanning so a scan
        # failure is retained in the log.
        if reset_log:
            try:
                clear_log_for_new_task()
            except Exception as e:
                tkMessageBox.showerror(
                    "Log file error",
                    "Cannot reset log file:\n%s\n\n%s" % (LOG_FILE, e)
                )
                return
            self.log_text.delete("1.0", "end")

        self.files_total = len(files)
        self.files_done = 0
        self.files_ok = 0
        self.files_error = 0
        self.files_skipped = 0

        self.progress["maximum"] = max(1, self.files_total)
        self.progress["value"] = 0

        self.update_counts()
        self.set_busy(True)


        thread = threading.Thread(
            target=self.worker,
            args=(files,)
        )
        thread.daemon = True
        thread.start()

    def worker(self, files):
        """Process each candidate independently and always restore the UI."""
        try:
            for index, src in enumerate(files):
                self.status(
                    "Processing %d/%d: %s" %
                    (index + 1, len(files), os.path.basename(src))
                )
                try:
                    unused_path, info = process_file(src)
                    if info and info.get("skipped"):
                        self.files_skipped += 1
                    else:
                        self.files_ok += 1
                except Exception as error:
                    self.files_error += 1
                    message = "[ERROR] %s: %s" % (src, error)
                    self.log(message)
                    LOGGER.exception("Worker failed for file: %s" % src)

                self.files_done += 1
                self.update_counts()
                self.safe_after(
                    0,
                    lambda value=self.files_done:
                        self.progress.configure(value=value)
                )
        except Exception:
            self.files_error += 1
            LOGGER.exception("Unexpected GUI worker-thread failure")
            self.log("[TASK ERROR] Unexpected failure; see log for traceback.")
        finally:
            self.set_busy(False)
            if self.files_error:
                self.status("Finished with errors")
            else:
                self.status("Finished")
            self.log(
                "SUMMARY: Finished. Total=%d Success=%d Skipped=%d Errors=%d" %
                (self.files_total, self.files_ok, self.files_skipped,
                 self.files_error)
            )


def main_gui():
    LOGGER.write("GUI START: Python=%s" % sys.version.replace("\n", " "))
    LOGGER.write("GUI SCRIPT: %s" % os.path.abspath(__file__))
    LOGGER.write("WORKER SCRIPT: %s" % get_worker_path())
    try:
        root = tk.Tk()
        DecompilerGUI(root)
        root.mainloop()
    except Exception:
        LOGGER.exception("FATAL GUI EXCEPTION")
        try:
            tkMessageBox.showerror(
                "BigWorld Decompiler - Fatal Error",
                "A fatal error occurred.\n\n"
                "Full traceback was saved to:\n%s" % LOG_FILE
            )
        except Exception:
            pass
        raise


def main_cli(args):
    log("CLI mode started")
    log("CLI arguments: %s" % repr(args))

    parser = argparse.ArgumentParser(
        description="BigWorld PackedSection -> UTF-8 XML"
    )
    parser.add_argument("input")
    parser.add_argument("output", nargs="?")
    parsed = parser.parse_args(args)

    src = os.path.abspath(parsed.input)

    if not os.path.isfile(src):
        print("ERROR: file not found:", src, file=sys.stderr)
        return 1

    try:
        if parsed.output:
            dst = os.path.abspath(parsed.output)
            info = decompile(src, dst)
        else:
            dst, info = process_file(src)
    except Exception as e:
        print("ERROR:", e, file=sys.stderr)
        return 2

    print("BigWorld PackedSection Decompiler")
    print("Input   :", src)
    print("Output  :", dst)
    print("Version :", info["version"])
    print("Strings :", info["strings"])
    print("Input   :", info["input_size"], "bytes")
    print("Output  :", info["output_size"], "bytes UTF-8")
    print("OK")
    return 0


if __name__ == "__main__":
    # Command-line mode:
    # python BigWorldDecompiler.py input [output]
    #
    # If output is omitted, input is overwritten with readable UTF-8 XML.
    # If output is specified, a separate output file is created.
    #
    # GUI mode:
    # python BigWorldDecompiler.py
    try:
        if len(sys.argv) > 1:
            sys.exit(main_cli(sys.argv[1:]))
        else:
            main_gui()
    except Exception:
        LOGGER.exception("FATAL UNHANDLED EXCEPTION")
        raise
