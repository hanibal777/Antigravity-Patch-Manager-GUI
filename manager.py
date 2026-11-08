#!/usr/bin/env python3
"""Patch Antigravity eligibility gates and verify component status."""
from __future__ import annotations
import argparse, contextlib, errno, filecmp, functools, glob, hashlib, json, mmap, os, plistlib, re, shutil, struct, subprocess, sys, tempfile, time
from concurrent.futures import ThreadPoolExecutor
from xml.parsers.expat import ExpatError
try:
    import winreg
except Exception:
    winreg = None

BAK = ".agybak"
MAC_SIGNATURE_BAK = ".agysignbak"
MAC_DISABLE_LIBRARY_VALIDATION = "com.apple.security.cs.disable-library-validation"
TARGETS = ("cli", "manager", "ide", "extension")

# Utilities
def _say(tag, msg): print(f"  [{tag}] {msg}")
def ok(m):   _say("ok", m)
def info(m): _say("..", m)
def warn(m): _say("!!", m)

def _patch_success(app, change, offset):
    ok(f"{app} patched ({change} @ file 0x{offset:x})")

def _bin(name):
    return name + (".exe" if os.name == "nt" else "")

def _mac_write_permission_hint(path, error):
    if (sys.platform == "darwin" and error.errno == errno.EPERM and
            _mac_app_bundle(path)):
        warn("macOS blocked modification of an app bundle; App Management permission may be required")
        info("open System Settings > Privacy & Security > App Management and enable the app running this command "
             "(your terminal app, or your editor when using its integrated terminal)")
        info("quit and reopen that terminal/editor, then retry; sudo does not grant macOS privacy permissions")
        return True
    return False

def is_locked(path, app=None):
    """Check write access, optionally reporting why the file cannot be opened."""
    try:
        with open(path, "r+b"):
            return False
    except OSError as e:
        # macOS can deny opening a signed executable for in-place writes even
        # when its owner can replace it. Probe the directory without touching it.
        if sys.platform == "darwin" and e.errno == errno.EPERM:
            try:
                actual = os.path.realpath(path)
                fd, probe = tempfile.mkstemp(prefix=".agy-write-", dir=os.path.dirname(actual))
                os.close(fd)
                os.unlink(probe)
                return False
            except OSError as probe_error:
                if app:
                    warn(f"cannot create a temporary replacement in {os.path.dirname(actual)}: {probe_error}")
        if app:
            if e.errno == errno.ETXTBSY or getattr(e, "winerror", None) in (32, 33):
                warn(f"{os.path.basename(path)} is in use — close {app} and its background processes first")
            elif e.errno in (errno.EACCES, errno.EPERM):
                if not _mac_write_permission_hint(path, e):
                    warn(f"permission denied writing {path} — use an account with write access to the installation")
                    info("check file permissions and directory permissions for the backup")
            else:
                warn(f"cannot open {path} for writing")
            warn(f"system error: {e}")
        return True

def _files_equal(first, second):
    """Read actual bytes on every check, including same-size/mtime rewrites."""
    with open(first, "rb") as a, open(second, "rb") as b:
        while True:
            chunk = a.read(1024 * 1024)
            if chunk != b.read(1024 * 1024):
                return False
            if not chunk:
                return True

def _binary_backup_matches(path, bak):
    """Recognize a pristine backup plus only our known binary replacements."""
    replacements = []
    try:
        ranges, arch = executable_info(bak)
        current_ranges, current_arch = executable_info(path)
        if arch != current_arch or os.path.getsize(path) != os.path.getsize(bak):
            return False
        with mapped(bak) as saved, mapped(path) as current:
            for gate in (CLI_GATE, MANAGER_GATE):
                try:
                    state, off, g = gate.resolve(saved, ranges, arch)
                except SignatureNotFound:
                    continue
                if state != "unpatched":
                    return False
                current_state, current_off, current_gate = gate.resolve(current, current_ranges, current_arch)
                if current_off != off or current_gate is not g:
                    return False
                if current_state == "patched":
                    replacements.append((off, g.fix))
        if not replacements:
            return False
        pos = 0
        with open(bak, "rb") as saved, open(path, "rb") as current:
            while chunk := saved.read(1024 * 1024):
                expected = bytearray(chunk)
                for off, fix in replacements:
                    start, end = max(off, pos), min(off + len(fix), pos + len(chunk))
                    if start < end:
                        expected[start - pos:end - pos] = fix[start - off:end - off]
                if current.read(len(chunk)) != expected:
                    return False
                pos += len(chunk)
        return True
    except (LookupError, OSError, ValueError):
        return False

def make_backup(path, binary=False):
    """Create or refresh a verified clean backup."""
    bak = path + BAK
    if os.path.exists(bak):
        if _files_equal(path, bak):
            if not binary or not any(gate_status(bak, gate)[0] == "patched" for gate in (CLI_GATE, MANAGER_GATE)):
                return bak
            raise OSError("backup already contains a binary patch; restore a pristine original before applying another target")
        if binary and _binary_backup_matches(path, bak):
            return bak
    if binary and any(gate_status(path, gate)[0] == "patched" for gate in (CLI_GATE, MANAGER_GATE)):
        raise OSError("cannot verify a pristine backup for the existing binary patch; restore the original before applying another target")
    if os.path.exists(bak):
        info(f"backup is stale (app updated) — refreshing {os.path.basename(path)}{BAK}")
    else:
        info(f"backup -> {os.path.basename(path)}{BAK}")
    shutil.copy2(path, bak)
    if not _files_equal(path, bak):
        raise OSError("backup verification failed")
    return bak

@contextlib.contextmanager
def _mac_staged_binary(path):
    """Create a private sibling inode; leave the installed binary untouched."""
    fd, staged = tempfile.mkstemp(prefix=".agy-write-", dir=os.path.dirname(path))
    os.close(fd)
    try:
        yield staged
    finally:
        if os.path.exists(staged):
            os.unlink(staged)

def _copy_binary(src, dst):
    if sys.platform != "darwin":
        shutil.copy2(src, dst)
        return
    dst = os.path.realpath(dst)
    with _mac_staged_binary(dst) as staged:
        shutil.copy2(src, staged)
        if not filecmp.cmp(src, staged, shallow=False):
            raise OSError("replacement copy verification failed")
        with open(staged, "r+b") as f:
            f.flush(); os.fsync(f.fileno())
        os.replace(staged, dst)

def restore_file(path, status=None):
    if sys.platform == "darwin":
        path = os.path.realpath(path)
    b = path + BAK
    if not os.path.exists(b):
        warn(f"no backup for {os.path.basename(path)} (nothing to restore)")
        return False
    if sys.platform == "darwin":
        app = _mac_app_bundle(path)
        if app and os.path.basename(path) == "language_server":
            if _mac_is_isolated_profile(app):
                try:
                    _desktop_namespace_credentials(b, os.path.dirname(app), check_only=True)
                except (OSError, ValueError, LookupError) as e:
                    warn(f"backup would break profile credential isolation — refusing to restore: {e}")
                    return False
    if is_locked(path, "the app"):
        return False
    if status:
        try:
            if status(b)[0] != "unpatched":
                warn("backup is not a recognized clean build — refusing to restore")
                return False
        except Exception as e:
            warn(f"couldn't validate backup: {e}"); return False
    _copy_binary(b, path)
    if status and status(path)[0] != "unpatched":
        warn("restore verification failed")
        return False
    ok(f"restored {os.path.basename(path)}")
    return True

def rmtree_quiet(p):
    try:
        if os.path.isdir(p): shutil.rmtree(p, ignore_errors=True)
    except OSError:
        pass

@contextlib.contextmanager
def mapped(path):
    """Yield scan data without mapping signed file pages on macOS."""
    with open(path, "rb") as f:
        with _scan_data(f) as data:
            yield data

@contextlib.contextmanager
def _scan_data(f):
    # Reading a modified signed Mach-O through mmap can cause an uncatchable
    # CODESIGNING SIGKILL on macOS, including during post-write verification.
    if sys.platform == "darwin":
        f.seek(0)
        yield f.read()
        return
    if os.fstat(f.fileno()).st_size == 0:
        yield b""; return
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    try: yield mm
    finally: mm.close()

def _read_exact(f, offset, size):
    f.seek(offset)
    data = f.read(size)
    if len(data) != size:
        raise ValueError("truncated executable header")
    return data

def _normalized_ranges(ranges, file_size):
    clean = []
    for start, end in ranges:
        start, end = max(0, start), min(file_size, end)
        if start < end: clean.append((start, end))
    out = []
    for start, end in sorted(clean):
        if out and start <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], end))
        else:
            out.append((start, end))
    return tuple(out)

def _machine_arch(machine):
    return {0x8664: "x64", 0xaa64: "arm64", 0x3e: "x64", 0xb7: "arm64",
            0x01000007: "x64", 0x0100000c: "arm64"}.get(machine)

def _pe_executable_info(f, file_size):
    pe = struct.unpack("<I", _read_exact(f, 0x3c, 4))[0]
    if _read_exact(f, pe, 4) != b"PE\0\0":
        raise ValueError("invalid PE signature")
    coff = _read_exact(f, pe + 4, 20)
    arch = _machine_arch(struct.unpack_from("<H", coff, 0)[0])
    section_count = struct.unpack_from("<H", coff, 2)[0]
    optional_size = struct.unpack_from("<H", coff, 16)[0]
    section_table = pe + 24 + optional_size
    ranges = []
    for i in range(section_count):
        section = _read_exact(f, section_table + i * 40, 40)
        raw_size, raw_offset = struct.unpack_from("<II", section, 16)
        characteristics = struct.unpack_from("<I", section, 36)[0]
        if characteristics & 0x20000000:
            ranges.append((raw_offset, raw_offset + raw_size))
    return _normalized_ranges(ranges, file_size), arch

def _elf_executable_info(f, file_size):
    ident = _read_exact(f, 0, 16)
    elf_class, data_order = ident[4], ident[5]
    endian = "<" if data_order == 1 else ">" if data_order == 2 else None
    if endian is None:
        raise ValueError("unknown ELF byte order")
    machine = struct.unpack(endian + "H", _read_exact(f, 18, 2))[0]
    if elf_class == 2:
        header = _read_exact(f, 0, 64)
        phoff = struct.unpack_from(endian + "Q", header, 32)[0]
        phentsize, phnum = struct.unpack_from(endian + "HH", header, 54)
        layout = (0, 4, 8, 32, "I", "I", "Q", "Q")
    elif elf_class == 1:
        header = _read_exact(f, 0, 52)
        phoff = struct.unpack_from(endian + "I", header, 28)[0]
        phentsize, phnum = struct.unpack_from(endian + "HH", header, 42)
        layout = (0, 24, 4, 16, "I", "I", "I", "I")
    else:
        raise ValueError("unknown ELF class")
    type_off, flags_off, file_off, size_off, type_fmt, flags_fmt, off_fmt, size_fmt = layout
    ranges = []
    for i in range(phnum):
        entry = _read_exact(f, phoff + i * phentsize, phentsize)
        p_type = struct.unpack_from(endian + type_fmt, entry, type_off)[0]
        flags = struct.unpack_from(endian + flags_fmt, entry, flags_off)[0]
        offset = struct.unpack_from(endian + off_fmt, entry, file_off)[0]
        size = struct.unpack_from(endian + size_fmt, entry, size_off)[0]
        if p_type == 1 and flags & 1:
            ranges.append((offset, offset + size))
    return _normalized_ranges(ranges, file_size), _machine_arch(machine)

def _macho_slice_info(f, file_size, base, slice_size):
    magic = _read_exact(f, base, 4)
    if magic == b"\xcf\xfa\xed\xfe":
        endian = "<"
    elif magic == b"\xfe\xed\xfa\xcf":
        endian = ">"
    else:
        raise ValueError("unsupported Mach-O slice")
    header = _read_exact(f, base, 32)
    arch = _machine_arch(struct.unpack_from(endian + "I", header, 4)[0])
    command_count = struct.unpack_from(endian + "I", header, 16)[0]
    pos, ranges = base + 32, []
    for _ in range(command_count):
        command_header = _read_exact(f, pos, 8)
        command, command_size = struct.unpack(endian + "II", command_header)
        if command_size < 8 or pos + command_size > base + slice_size:
            raise ValueError("invalid Mach-O load command")
        if command == 0x19:
            segment = _read_exact(f, pos, command_size)
            section_count = struct.unpack_from(endian + "I", segment, 64)[0]
            if 72 + section_count * 80 > command_size:
                raise ValueError("invalid Mach-O section table")
            section_pos = 72
            for _ in range(section_count):
                section = segment[section_pos:section_pos + 80]
                section_name = section[:16].split(b"\0", 1)[0]
                segment_name = section[16:32].split(b"\0", 1)[0]
                size = struct.unpack_from(endian + "Q", section, 40)[0]
                offset = struct.unpack_from(endian + "I", section, 48)[0]
                flags = struct.unpack_from(endian + "I", section, 64)[0]
                is_code = ((segment_name, section_name) == (b"__TEXT", b"__text") or
                           flags & (0x80000000 | 0x00000400))
                if is_code:
                    ranges.append((base + offset, base + offset + size))
                section_pos += 80
        pos += command_size
    return _normalized_ranges(ranges, file_size), arch

def _macho_executable_info(f, file_size):
    magic = _read_exact(f, 0, 4)
    if magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
        return _macho_slice_info(f, file_size, 0, file_size)
    fat = {
        b"\xca\xfe\xba\xbe": (">", False), b"\xbe\xba\xfe\xca": ("<", False),
        b"\xca\xfe\xba\xbf": (">", True),  b"\xbf\xba\xfe\xca": ("<", True),
    }.get(magic)
    if not fat:
        raise ValueError("unsupported Mach-O header")
    endian, is_64 = fat
    count = struct.unpack(endian + "I", _read_exact(f, 4, 4))[0]
    entry_size = 32 if is_64 else 20
    ranges, arches = [], []
    for i in range(count):
        entry = _read_exact(f, 8 + i * entry_size, entry_size)
        if is_64:
            offset, size = struct.unpack_from(endian + "QQ", entry, 8)
        else:
            offset, size = struct.unpack_from(endian + "II", entry, 8)
        slice_ranges, arch = _macho_slice_info(f, file_size, offset, size)
        ranges += slice_ranges
        arches.append(arch)
    known_arch = arches[0] if arches and arches[0] and all(a == arches[0] for a in arches) else None
    return _normalized_ranges(ranges, file_size), known_arch

def executable_info(path):
    """Return executable file ranges and architecture for PE, ELF, or Mach-O."""
    with open(path, "rb") as f:
        file_size = os.fstat(f.fileno()).st_size
        magic = _read_exact(f, 0, min(4, file_size))
        if magic[:2] == b"MZ":
            ranges, arch = _pe_executable_info(f, file_size)
        elif magic == b"\x7fELF":
            ranges, arch = _elf_executable_info(f, file_size)
        else:
            ranges, arch = _macho_executable_info(f, file_size)
    if not ranges:
        raise ValueError("no executable code ranges found")
    return ranges, arch

def executable_ranges(path):
    """Return executable file ranges for PE, ELF, or Mach-O."""
    return executable_info(path)[0]

# Discovery
@functools.lru_cache(maxsize=1)
def _reg_install_dirs():
    dirs = []
    if not winreg: return dirs
    for hive, sub in ((winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
                      (winreg.HKEY_LOCAL_MACHINE,  r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
                      (winreg.HKEY_LOCAL_MACHINE,  r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")):
        try: key = winreg.OpenKey(hive, sub)
        except OSError: continue
        try: cnt = winreg.QueryInfoKey(key)[0]
        except OSError: cnt = 0
        for i in range(cnt):
            try:
                s = winreg.OpenKey(key, winreg.EnumKey(key, i))
                if "antigravity" in str(winreg.QueryValueEx(s, "DisplayName")[0]).lower():
                    loc = winreg.QueryValueEx(s, "InstallLocation")[0]
                    if loc: dirs.append(loc)
            except OSError:
                pass
    return dirs

@functools.lru_cache(maxsize=1)
def _roots():
    out = []
    for v in ("LOCALAPPDATA", "ProgramW6432", "PROGRAMFILES", "PROGRAMFILES(X86)", "ProgramData", "APPDATA"):
        p = os.environ.get(v)
        if not p: continue
        out += [p, os.path.join(p, "Programs")]
    up = os.environ.get("USERPROFILE", "")
    out += [os.path.join(up, "scoop", "apps"), os.path.join(os.environ.get("SCOOP", ""), "apps")]
    out += _reg_install_dirs()
    seen, roots = set(), []
    for r in out:
        if r and os.path.isdir(r):
            k = os.path.normcase(os.path.realpath(r))
            if k not in seen: seen.add(k); roots.append(r)
    return roots

def _dedup_newest(paths):
    seen, out = set(), []
    for p in sorted({p for p in paths if os.path.exists(p)},
                    key=lambda x: os.path.getmtime(x), reverse=True):
        k = os.path.normcase(os.path.realpath(p))
        if k not in seen: seen.add(k); out.append(p)
    return out

def find_marker(rel):
    """Find a marker below known Windows install roots."""
    hits = []
    for root in _roots():
        hits += glob.glob(os.path.join(root, "*ntigravity*", rel))
        hits += glob.glob(os.path.join(root, "*ntigravity*", "*", rel))
        direct = os.path.join(root, rel)
        if os.path.isfile(direct): hits.append(direct)
    return _dedup_newest(hits)

def _posix_install_roots(*launchers):
    home = os.path.expanduser("~")
    roots = ["/opt", "/usr/share", "/usr/lib", "/usr/local/share", "/usr/local/lib",
             "/Applications",
             os.path.join(home, ".local", "share"),
             os.path.join(home, "Applications"),
             os.path.join(home, "Downloads"), home]
    for launcher in launchers:
        w = shutil.which(launcher)
        if w: roots.append(os.path.dirname(os.path.realpath(w)))
    return roots

def _posix_find(rel, *launchers):
    """Find a marker below known POSIX install roots."""
    hits = []
    for root in _posix_install_roots(*launchers):
        hits += glob.glob(os.path.join(root, "*ntigravity*", rel))
        hits += glob.glob(os.path.join(root, "*ntigravity*", "*", rel))
        direct = os.path.join(root, rel)
        if os.path.isfile(direct): hits.append(direct)
    return _dedup_newest(hits)

# Binary gates; re.S lets wildcards match every displacement byte.
class SignatureNotFound(LookupError):
    pass

class SignatureAmbiguous(LookupError):
    pass

def _unique_match(pattern, data, ranges, label, accept=None):
    found = None
    for start, end in ranges:
        pos = start
        while pos < end:
            match = pattern.search(data, pos, end)
            if not match:
                break
            if accept is not None and not accept(data, match, start, end):
                pos = max(match.end(), match.start() + 1)
                continue
            if found is not None:
                raise SignatureAmbiguous(f"{label} signature is not unique — refusing to guess")
            found = match
            pos = max(match.end(), match.start() + 1)
    return found

class Gate:
    def __init__(self, sig, patched, fix, offset=0, desc="", arch=None, accept=None):
        self.sig, self.patched = re.compile(sig, re.S), re.compile(patched, re.S)
        self.fix, self.offset, self.desc, self.arch, self.accept = fix, offset, desc, arch, accept
    def find(self, data, ranges=None):
        """Return state and write offset for one unambiguous signature."""
        search_ranges = ranges or ((0, len(data)),)
        original = _unique_match(self.sig, data, search_ranges, "unpatched gate", self.accept)
        patched = _unique_match(self.patched, data, search_ranges, "patched gate", self.accept)
        if original and patched:
            raise SignatureAmbiguous("both patched and unpatched gate signatures are present")
        if patched:
            return ("patched", patched.start() + self.offset)
        if original:
            return ("unpatched", original.start() + self.offset)
        raise SignatureNotFound("gate signature not found (unsupported version?)")
    def resolve(self, data, ranges=None, arch=None):
        kind, off = self.find(data, ranges)
        return kind, off, self

class MultiGate:
    """Select one architecture-specific gate."""
    def __init__(self, *gates, desc=""):
        self.gates, self.desc = gates, desc
    def resolve(self, data, ranges=None, arch=None):
        matches = []
        gates = [g for g in self.gates
                 if arch is None or getattr(g, "arch", None) is None or g.arch == arch]
        for g in gates:
            try:
                matches.append(g.resolve(data, ranges, arch))
            except SignatureNotFound:
                pass
        if len(matches) > 1:
            raise SignatureAmbiguous("multiple architecture gate signatures matched")
        if matches:
            return matches[0]
        raise SignatureNotFound("no architecture gate signature matched (unsupported version?)")

def gate_status(path, gate):
    try:
        ranges, arch = executable_info(path)
        with mapped(path) as d:
            return (gate.resolve(d, ranges, arch)[0], None)
    except (LookupError, OSError, ValueError):
        return ("unknown", None)

def gate_patch(path, gate, app, fname):
    if sys.platform == "darwin":
        path = os.path.realpath(path)
    if is_locked(path, app):
        return False
    try:
        ranges, arch = executable_info(path)
        with mapped(path) as d:
            kind, off, g = gate.resolve(d, ranges, arch)
    except (LookupError, OSError, ValueError) as e:
        warn(str(e)); return False
    if kind == "patched":
        ok(f"{app} already patched"); return True
    bak = make_backup(path, binary=True)
    try:
        # A CLI and extension can share agy. Preserve the pristine disk backup;
        # use a separate snapshot to rescan and roll back this operation only.
        with tempfile.TemporaryDirectory(prefix="agy-patch-") as temp:
            before = os.path.join(temp, "before")
            shutil.copy2(path, before)
            if not _files_equal(path, before):
                raise OSError("patch snapshot verification failed")
            if not _files_equal(before, bak) and not _binary_backup_matches(before, bak):
                raise OSError("target changed after backup")
            return _gate_write(path, gate, off, g, before, app)
    except Exception as e:
        warn(f"{app} patch failed: {e}")
        return False

def _gate_write(path, gate, off, g, before, app):
    write_started = False
    try:
        if not _files_equal(path, before):
            raise OSError("target changed after backup")
        staging = _mac_staged_binary(path) if sys.platform == "darwin" else contextlib.nullcontext(path)
        with staging as writable:
            if writable != path:
                shutil.copy2(path, writable)
                if not _files_equal(writable, before):
                    raise OSError("target changed while staging patch")
            ranges, arch = executable_info(writable)
            with open(writable, "r+b") as f:
                with _scan_data(f) as data:
                    current_kind, current_off, current_gate = gate.resolve(data, ranges, arch)
                if current_kind != "unpatched" or current_off != off or current_gate is not g:
                    raise OSError("target changed before patch write")
                f.seek(off)
                if writable == path:
                    write_started = True
                f.write(g.fix); f.flush(); os.fsync(f.fileno())
            if writable != path:
                with mapped(writable) as data:
                    if gate.resolve(data, ranges, arch) != ("patched", off, g):
                        raise OSError("staged signature verification failed")
                ranges, arch = executable_info(path)
                with mapped(path) as data:
                    current = gate.resolve(data, ranges, arch)
                if current != ("unpatched", off, g) or not _files_equal(path, before):
                    raise OSError("target changed before patch replacement")
                os.replace(writable, path)
                write_started = True
        ranges, arch = executable_info(path)
        with mapped(path) as d:
            final_kind, final_off, final_gate = gate.resolve(d, ranges, arch)
        if final_kind != "patched" or final_off != off or final_gate is not g:
            raise OSError("post-write signature verification failed")
    except Exception as e:
        try:
            if write_started:
                _copy_binary(before, path)
            rolled_back = _files_equal(path, before)
        except Exception:
            rolled_back = False
        warn(f"{app} patch failed: {e}")
        if isinstance(e, OSError):
            _mac_write_permission_hint(path, e)
        warn("state before this patch restored" if rolled_back else
             f"automatic rollback failed — restore {os.path.basename(path) + BAK} manually")
        return False
    _patch_success(app, g.desc, off)
    return True

# CLI eligibility screen
# CLI 1.4.0 x64 handleAuthResult: test rcx,rcx ; je ; cmp byte[rcx+8],0 ; jne eligible ;
# mov rax,rcx ; nop ; call IneligibilityFromResult ; spill rax/rbx/rcx at +0xe0/+0xe8/+0xf0.
# Repeating test rcx,rcx keeps ZF=0, so jne selects eligible without changing the formatter.
CLI_GATE_X64 = Gate(
    rb"\x48\x85\xc9\x0f\x84....\x80\x79\x08\x00\x0f\x85....\x48\x89\xc8\x90"
    rb"\xe8....\x48\x89\x84\x24\xe0\x00\x00\x00"
    rb"\x48\x89\x9c\x24\xe8\x00\x00\x00\x48\x89\x8c\x24\xf0\x00\x00\x00",
    rb"\x48\x85\xc9\x0f\x84....\x48\x85\xc9\x90\x0f\x85....\x48\x89\xc8\x90"
    rb"\xe8....\x48\x89\x84\x24\xe0\x00\x00\x00"
    rb"\x48\x89\x9c\x24\xe8\x00\x00\x00\x48\x89\x8c\x24\xf0\x00\x00\x00",
    b"\x48\x85\xc9\x90", offset=9, desc="eligibility screen off (x64)", arch="x64")

def _cli_arm64_context(data, match, start, end):
    off = match.start()
    if off - 8 < start:
        return False
    cbnz_x1, cbz_x0 = struct.unpack_from("<II", data, off - 8)
    return ((cbnz_x1 & 0xff00001f) == 0xb5000001 and
            (cbz_x0 & 0xff00001f) == 0xb4000000)

# CLI 1.4.0 arm64: ldrb w2,[x0,#8] ; tbnz w2,#0,eligible ;
# bl IneligibilityFromResult ; stp x0-x7 at +0xe8/+0xf8/+0x108/+0x118.
# mov w2,#1 selects the existing eligible branch.
CLI_GATE_ARM64 = Gate(
    rb"\x02\x20\x40\x39[\x02\x22\x42\x62\x82\xa2\xc2\xe2].[\x00-\x07]\x37"
    rb"...[\x94-\x97]\xe0\x87\x0e\xa9\xe2\x8f\x0f\xa9\xe4\x97\x10\xa9\xe6\x9f\x11\xa9",
    rb"\x22\x00\x80\x52[\x02\x22\x42\x62\x82\xa2\xc2\xe2].[\x00-\x07]\x37"
    rb"...[\x94-\x97]\xe0\x87\x0e\xa9\xe2\x8f\x0f\xa9\xe4\x97\x10\xa9\xe6\x9f\x11\xa9",
    b"\x22\x00\x80\x52", desc="eligibility screen off (arm64)",
    arch="arm64", accept=_cli_arm64_context)

CLI_GATE = MultiGate(CLI_GATE_X64, CLI_GATE_ARM64, desc="eligibility screen off")


def cli_default_paths():
    cands = []
    w = shutil.which("agy")
    if w:
        base, ext = os.path.splitext(w); cands.append(base + ext.lower())
    if os.name == "nt":
        for root in _roots():
            cands += glob.glob(os.path.join(root, "agy", "bin", "agy.exe"))
            cands += glob.glob(os.path.join(root, "agy", "*", "bin", "agy.exe"))
            cands += glob.glob(os.path.join(root, "agy*", "agy.exe"))
    else:
        home = os.path.expanduser("~")
        cands += [os.path.join(d, "agy") for d in
                  (os.path.join(home, ".local", "bin"), os.path.join(home, "bin"),
                   "/usr/local/bin", "/usr/bin", "/opt/homebrew/bin")]
    return _dedup_newest(cands)

# Manager auth result
# Manager 2.19.1 Windows x64: force hasValidAuth and fall through to token attachment.
# cmp byte[rax+8],0 ; je ; mov rdx,[rsp+0x70] ; mov [rax+0x60],rdx
# Replacing cmp/je with mov byte[rax+8],1 ; nop*2 selects the success path.
MANAGER_GATE_X64 = Gate(rb"\x80\x78\x08\x00\x74.\x48\x8b\x54\x24\x70\x48\x89\x50\x60",
                        rb"\xc6\x40\x08\x01\x90\x90\x48\x8b\x54\x24\x70\x48\x89\x50\x60",
                        b"\xc6\x40\x08\x01\x90\x90", desc="hasValidAuth=true", arch="x64")

# Manager 2.19.1 Linux arm64: verified against the archive's language_server.
# Force hasValidAuth and remove the token-attachment branch.
#   ldrb w3,[x0,#8] ; tbz w3,#0,skip  ->  mov w3,#1 ; strb w3,[x0,#8]
# Keep the current ldp x3,x4,[sp,#0x80] ; stp x3,x4,[x0,#0x60] context.
# Only the tbz displacement varies; Rt=w3 and bit #0 stay fixed.
MANAGER_GATE_ARM64 = Gate(rb"\x03\x20\x40\x39[\x03\x23\x43\x63\x83\xa3\xc3\xe3]."
                          rb"[\x00-\x07]\x36\xe3\x13\x48\xa9\x03\x10\x06\xa9",
                          rb"\x23\x00\x80\x52\x03\x20\x00\x39\xe3\x13\x48\xa9"
                          rb"\x03\x10\x06\xa9",
                          b"\x23\x00\x80\x52\x03\x20\x00\x39", desc="hasValidAuth=true (arm64)",
                          arch="arm64")

MANAGER_GATE = MultiGate(MANAGER_GATE_X64, MANAGER_GATE_ARM64, desc="hasValidAuth=true")

# Extension 1.7.0 uses agy 1.3.0 --hub: its verified Windows x64 validator
# has the same cmp/je and token-attachment instructions as Manager 2.19.1.
# ARM64 extension builds require their own verification before enabling them.
EXTENSION_GATE = MultiGate(MANAGER_GATE_X64, desc="hub hasValidAuth=true")

def extension_default_paths():
    return _dedup_newest([os.path.join(os.path.expanduser("~"), ".gemini", "bin", _bin("agy"))])

def manager_default_bins():
    if os.name == "nt":
        return find_marker(os.path.join("resources", "bin", "language_server.exe"))
    rel = (os.path.join("Contents", "Resources", "bin", "language_server") if sys.platform == "darwin"
           else os.path.join("resources", "bin", "language_server"))
    return _posix_find(rel, "antigravity")

# IDE
# IDE 2.5.5 macOS arm64: gate recognition reported in issue #8; JavaScript is arch-independent.
# Replace this.<minified field>.isGoogleInternal with true after resetIsTierGCPTos().
IDE_RE = re.compile(rb"(resetIsTierGCPTos\(\),)this\.[A-Za-z_$0-9]+\.isGoogleInternal")
IDE_DONE = b"resetIsTierGCPTos(),true"
IDE_DONE_RE = re.compile(re.escape(IDE_DONE))

def ide_default_mains():
    if os.name == "nt":
        return find_marker(os.path.join("resources", "app", "out", "main.js"))
    rel = (os.path.join("Contents", "Resources", "app", "out", "main.js") if sys.platform == "darwin"
           else os.path.join("resources", "app", "out", "main.js"))
    return _posix_find(rel, "antigravity-ide", "antigravity")

def _ide_gate_state(data):
    ranges = ((0, len(data)),)
    original = _unique_match(IDE_RE, data, ranges, "unpatched IDE gate")
    patched = _unique_match(IDE_DONE_RE, data, ranges, "patched IDE gate")
    if original and patched:
        raise SignatureAmbiguous("both patched and unpatched IDE gates are present")
    if original:
        return "unpatched"
    if patched:
        return "patched"
    raise SignatureNotFound("IDE auth-gate pattern not found (unsupported version?)")

def ide_status(path):
    try:
        with mapped(path) as d:
            return (_ide_gate_state(d), None)
    except (LookupError, OSError, ValueError):
        return ("unknown", None)

def _ide_cache_dirs():
    """Return JavaScript cache directories invalidated by the patch."""
    home = os.path.expanduser("~")
    if os.name == "nt":
        bases = [os.path.expandvars(p) for p in
                 (r"%USERPROFILE%\scoop\persist\antigravity-ide\data\user-data",
                  r"%APPDATA%\Antigravity IDE")]
    elif sys.platform == "darwin":
        bases = [os.path.join(home, "Library", "Application Support", "Antigravity IDE")]
    else:
        cfg = os.environ.get("XDG_CONFIG_HOME") or os.path.join(home, ".config")
        bases = [os.path.join(cfg, "Antigravity IDE")]
    dirs = []
    for base in bases:
        dirs += [os.path.join(base, "CachedData"),
                 os.path.join(base, "Code Cache", "js")]
    return dirs

def ide_patch(path):
    if is_locked(path, "Antigravity IDE"): return False
    with open(path, "rb") as f: d = f.read()
    try:
        kind = _ide_gate_state(d)
    except LookupError as e:
        warn(str(e)); return False
    if kind == "patched":
        ok("IDE already patched"); return True
    off = IDE_RE.search(d).end(1)
    bak = make_backup(path)
    try:
        with open(path, "rb") as f:
            current = f.read()
        if current != d or _ide_gate_state(current) != "unpatched":
            raise OSError("target changed before patch write")
        patched, count = IDE_RE.subn(rb"\1true", current, count=1)
        if count != 1:
            raise OSError(f"expected one IDE gate replacement, got {count}")
        with open(path, "wb") as f:
            f.write(patched); f.flush(); os.fsync(f.fileno())
        with mapped(path) as verified:
            if _ide_gate_state(verified) != "patched":
                raise OSError("post-write IDE signature verification failed")
    except Exception as e:
        try:
            shutil.copy2(bak, path)
            rolled_back = _files_equal(path, bak)
        except Exception:
            rolled_back = False
        warn(f"IDE patch failed: {e}")
        warn("original restored from backup" if rolled_back else
             f"automatic rollback failed — restore {os.path.basename(bak)} manually")
        return False
    for c in _ide_cache_dirs(): rmtree_quiet(c)
    _patch_success("IDE", "isGoogleInternal=true", off)
    return True

# Driver
SPEC = {
    "cli":     dict(name="Antigravity CLI",      find=cli_default_paths,     status=functools.partial(gate_status, gate=CLI_GATE),
                    patch=functools.partial(gate_patch, gate=CLI_GATE, app="CLI", fname=_bin("agy"))),
    "manager": dict(name="Antigravity Manager",  find=manager_default_bins,  status=functools.partial(gate_status, gate=MANAGER_GATE),
                    patch=functools.partial(gate_patch, gate=MANAGER_GATE, app="Manager", fname=_bin("language_server"))),
    "ide":     dict(name="Antigravity IDE",      find=ide_default_mains,     status=ide_status,     patch=ide_patch),
    "extension": dict(name="Antigravity IDE Extension", find=extension_default_paths,
                      status=functools.partial(gate_status, gate=EXTENSION_GATE),
                      patch=functools.partial(gate_patch, gate=EXTENSION_GATE, app="IDE Extension", fname=_bin("agy"))),
}


# macOS code signing
def _mac_app_bundle(path):
    """Return the enclosing .app bundle, if path is inside one."""
    cur = os.path.realpath(path)
    if not os.path.isdir(cur):
        cur = os.path.dirname(cur)
    while True:
        if cur.endswith(".app") and os.path.isdir(os.path.join(cur, "Contents")):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            return None
        cur = parent


def _mac_bundle_main(app):
    info_path = os.path.join(app, "Contents", "Info.plist")
    with open(info_path, "rb") as f:
        executable = plistlib.load(f).get("CFBundleExecutable")
    if not isinstance(executable, str) or not executable or os.path.basename(executable) != executable:
        raise ValueError("invalid CFBundleExecutable in macOS app bundle")
    path = os.path.join(app, "Contents", "MacOS", executable)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"app bundle executable not found: {path}")
    return path


def _mac_entry_kind(path):
    if os.path.islink(path):
        return "symlink"
    if os.path.isdir(path):
        return "dir"
    if os.path.isfile(path):
        return "file"
    return "missing"


def _mac_entry_digest(path):
    h = hashlib.sha256()

    def add(cur, rel):
        kind = _mac_entry_kind(cur)
        h.update(kind.encode() + b"\0" + rel.encode("utf-8", "surrogateescape") + b"\0")
        if kind == "symlink":
            h.update(os.readlink(cur).encode("utf-8", "surrogateescape"))
        elif kind == "file":
            h.update(str(os.stat(cur, follow_symlinks=False).st_mode & 0o7777).encode())
            with open(cur, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
        elif kind == "dir":
            for name in sorted(os.listdir(cur)):
                add(os.path.join(cur, name), rel + "/" + name if rel else name)

    add(path, "")
    return h.hexdigest()


def _mac_remove_entry(path):
    if os.path.islink(path) or os.path.isfile(path):
        os.unlink(path)
    elif os.path.isdir(path):
        shutil.rmtree(path)


def _mac_copy_entry(src, dst):
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    kind = _mac_entry_kind(src)
    if kind == "symlink":
        os.symlink(os.readlink(src), dst)
    elif kind == "dir":
        shutil.copytree(src, dst, symlinks=True, copy_function=shutil.copy2)
    elif kind == "file":
        shutil.copy2(src, dst)


def _mac_signature_relpaths(app):
    main = os.path.relpath(_mac_bundle_main(app), app)
    return (main, os.path.join("Contents", "_CodeSignature"),
            os.path.join("Contents", "CodeResources"))


def _mac_write_signature_snapshot(app, snapshot):
    app = os.path.abspath(app)
    payload = os.path.join(snapshot, "payload")
    os.makedirs(payload, exist_ok=True)
    items = []
    for rel in _mac_signature_relpaths(app):
        src = os.path.join(app, rel)
        kind = _mac_entry_kind(src)
        if kind != "missing":
            _mac_copy_entry(src, os.path.join(payload, rel))
        items.append({"path": rel.replace(os.sep, "/"), "kind": kind,
                      "digest": _mac_entry_digest(src)})
    manifest = {"version": 1, "app": app, "items": items}
    with open(os.path.join(snapshot, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, sort_keys=True)
        f.flush(); os.fsync(f.fileno())
    _mac_validate_signature_snapshot(snapshot, app)


def _mac_load_signature_snapshot(snapshot, app):
    with open(os.path.join(snapshot, "manifest.json"), encoding="utf-8") as f:
        manifest = json.load(f)
    app = os.path.abspath(app)
    if manifest.get("version") != 1 or os.path.abspath(manifest.get("app", "")) != app:
        raise OSError("macOS signature backup belongs to a different app bundle")
    items = manifest.get("items")
    if not isinstance(items, list) or not items:
        raise OSError("invalid macOS signature backup manifest")
    for item in items:
        rel = item.get("path", "").replace("/", os.sep)
        dst = os.path.abspath(os.path.join(app, rel))
        if (not rel or os.path.isabs(rel) or
                os.path.normcase(os.path.commonpath((app, dst))) != os.path.normcase(app)):
            raise OSError("unsafe path in macOS signature backup")
    return manifest


def _mac_validate_signature_snapshot(snapshot, app):
    manifest = _mac_load_signature_snapshot(snapshot, app)
    for item in manifest["items"]:
        rel = item["path"].replace("/", os.sep)
        saved = os.path.join(snapshot, "payload", rel)
        if _mac_entry_kind(saved) != item["kind"]:
            raise OSError("macOS signature backup type verification failed")
        if _mac_entry_digest(saved) != item["digest"]:
            raise OSError("macOS signature backup content verification failed")
    return manifest


def _mac_restore_signature_snapshot(snapshot, app):
    manifest = _mac_validate_signature_snapshot(snapshot, app)
    app = os.path.abspath(app)
    for item in manifest["items"]:
        rel = item["path"].replace("/", os.sep)
        dst = os.path.join(app, rel)
        _mac_remove_entry(dst)
        if item["kind"] != "missing":
            _mac_copy_entry(os.path.join(snapshot, "payload", rel), dst)
            if _mac_entry_digest(dst) != item["digest"]:
                raise OSError("restored macOS signature state failed verification")


def _mac_bundle_patch_states(app):
    candidates = {
        "manager": os.path.join(app, "Contents", "Resources", "bin", "language_server"),
        "ide": os.path.join(app, "Contents", "Resources", "app", "out", "main.js"),
    }
    states = {}
    for target, path in candidates.items():
        if os.path.isfile(path):
            try:
                states[target] = (SPEC[target]["status"](path)[0], path)
            except Exception:
                states[target] = ("unknown", path)
    return states


def _mac_prepare_signature_backup(app):
    backup = app + MAC_SIGNATURE_BAK
    states = _mac_bundle_patch_states(app)
    clean = bool(states) and all(state == "unpatched" for state, _ in states.values())
    if sys.platform == "darwin":
        verify = _mac_command(["/usr/bin/codesign", "--verify", "--deep", "--strict",
                               "--verbose=2", app], check=False)
        display = _mac_command(["/usr/bin/codesign", "-d", "--verbose=2", app], check=False)
        details = (display.stdout + display.stderr).lower()
        clean = verify.returncode == 0 and "signature=adhoc" not in details
    if os.path.isdir(backup) and not clean:
        _mac_validate_signature_snapshot(backup, app)
        return backup

    parent = os.path.dirname(app)
    temp = tempfile.mkdtemp(prefix=os.path.basename(app) + MAC_SIGNATURE_BAK + ".", dir=parent)
    old = None
    try:
        _mac_write_signature_snapshot(app, temp)
        if os.path.lexists(backup):
            old = backup + f".old-{os.getpid()}-{time.time_ns()}"
            os.replace(backup, old)
        try:
            os.replace(temp, backup)
            temp = None
        except Exception:
            if old is not None:
                os.replace(old, backup)
                old = None
            raise
        if old is not None:
            _mac_remove_entry(old)
        info(f"macOS signature backup -> {os.path.basename(backup)}")
        return backup
    finally:
        if temp and os.path.isdir(temp):
            shutil.rmtree(temp, ignore_errors=True)


def _mac_command(args, check=True):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, encoding="utf-8", errors="replace")
    if check and result.returncode:
        detail = (result.stderr or result.stdout).strip().splitlines()
        raise OSError(detail[-1] if detail else f"command failed ({result.returncode}): {args[0]}")
    return result


def _mac_entitlements(path):
    result = _mac_command(["/usr/bin/codesign", "-d", "--entitlements", "-", "--xml", path])
    if not result.stdout.strip():
        return {}
    try:
        entitlements = plistlib.loads(result.stdout.encode("utf-8"))
    except (ValueError, ExpatError):
        raise OSError("cannot parse macOS signing entitlements") from None
    if not isinstance(entitlements, dict):
        raise OSError("macOS signing entitlements must be a dictionary")
    return entitlements


def _mac_library_validation_entitlements(app, allow_disable=False):
    """Plan an explicit Electron signing exception before any patch writes."""
    framework = os.path.join(app, "Contents", "Frameworks", "Electron Framework.framework")
    if not os.path.isdir(framework):
        return None
    _mac_bundle_main(app)  # Validate the executable covered by the bundle signature.
    display = _mac_command(["/usr/bin/codesign", "-d", "--verbose=4", app])
    details = display.stdout + display.stderr
    flags = re.search(r"\bflags=0x([0-9a-fA-F]+)\b", details)
    if not flags:
        raise OSError("cannot determine Electron code-signing flags before patching")
    # CS_RUNTIME enables Library Validation; CS_REQUIRE_LV requests it explicitly.
    if not int(flags[1], 16) & (0x10000 | 0x2000):
        return None
    entitlements = _mac_entitlements(app)
    exception = entitlements.get(MAC_DISABLE_LIBRARY_VALIDATION, False)
    if not isinstance(exception, bool):
        raise OSError("invalid Electron disable-library-validation entitlement")
    if exception:
        return None
    framework_display = _mac_command(["/usr/bin/codesign", "-d", "--verbose=4", framework])
    framework_details = framework_display.stdout + framework_display.stderr
    team = re.search(r"^TeamIdentifier=(.*)$", framework_details, re.M)
    if not team:
        raise OSError("cannot determine Electron Framework Team ID before patching")
    if not allow_disable:
        raise OSError(
            "Electron Library Validation would reject bundled frameworks after ad-hoc signing "
            f"(Electron Framework Team ID: {team[1].strip()}; ad-hoc Team ID: none). "
            "No patch was applied. To permit other/unsigned libraries in this app's main executable, "
            "rerun patch with --macos-disable-library-validation")
    return {**entitlements, MAC_DISABLE_LIBRARY_VALIDATION: True}


def _mac_codesign(path, bundle=False, entitlements=None, identifier=None):
    display = _mac_command(["/usr/bin/codesign", "-d", "--verbose=2", path], check=False)
    if entitlements is not None and display.returncode:
        raise OSError("cannot preserve Electron signing metadata before applying the Library Validation exception")
    args = ["/usr/bin/codesign", "--force", "--sign", "-"]
    if identifier is not None:
        args += ["--identifier", identifier]
    if display.returncode == 0:
        metadata = "identifier,flags,runtime" if entitlements is not None else "identifier,entitlements,flags,runtime"
        if identifier is not None:
            metadata = metadata.replace("identifier,", "")
        args.append("--preserve-metadata=" + metadata)
    with tempfile.TemporaryDirectory(prefix="agy-macos-entitlements-") as temp:
        if entitlements is not None:
            if not bundle:
                raise ValueError("Library Validation exceptions are limited to the app bundle's main executable")
            plist = os.path.join(temp, "entitlements.plist")
            with open(plist, "wb") as f:
                plistlib.dump(entitlements, f)
            args += ["--entitlements", plist]
            warn(f"disabling Library Validation for {os.path.basename(path)} main executable only; "
                 "this permits libraries with other or no signatures")
        _mac_command(args + [path])
        _mac_codesign_verify(path, bundle=bundle)
        if entitlements is not None and _mac_entitlements(path) != entitlements:
            raise OSError("signed macOS entitlements do not match the requested entitlements")


def _mac_sign_transaction(entries, bundle_entitlements=None):
    binaries = []
    bundles = []
    for target, path in entries.items():
        actual = os.path.realpath(path)
        if target in ("cli", "manager", "extension") and actual not in binaries:
            binaries.append(actual)
        app = _mac_app_bundle(path)
        if app and app not in bundles:
            bundles.append(app)
    if not binaries and not bundles:
        return

    with tempfile.TemporaryDirectory(prefix="agy-macos-sign-") as temp:
        binary_copies = []
        bundle_copies = []
        for i, path in enumerate(binaries):
            saved = os.path.join(temp, f"binary-{i}")
            shutil.copy2(path, saved)
            if not _files_equal(path, saved):
                raise OSError("temporary macOS signing backup verification failed")
            binary_copies.append((path, saved))
        for i, app in enumerate(bundles):
            saved = os.path.join(temp, f"bundle-{i}")
            os.makedirs(saved)
            _mac_write_signature_snapshot(app, saved)
            bundle_copies.append((app, saved))
        try:
            for path in binaries:
                _mac_codesign(path)
            for app in bundles:
                entitlements = (bundle_entitlements or {}).get(app)
                if entitlements is None:
                    _mac_codesign(app, bundle=True)
                else:
                    _mac_codesign(app, bundle=True, entitlements=entitlements)
            for path in binaries:
                ok(f"ad-hoc signed {os.path.basename(path)}")
            for app in bundles:
                ok(f"ad-hoc signed {os.path.basename(app)}")
        except Exception:
            restore_errors = []
            for path, saved in binary_copies:
                try:
                    _copy_binary(saved, path)
                except Exception as e:
                    restore_errors.append(str(e))
            for app, saved in bundle_copies:
                try:
                    _mac_restore_signature_snapshot(saved, app)
                except Exception as e:
                    restore_errors.append(str(e))
            if restore_errors:
                raise OSError("macOS signing failed and its temporary state could not be restored: " +
                              "; ".join(restore_errors))
            raise


def _mac_restore_bundle_signature(app):
    backup = app + MAC_SIGNATURE_BAK
    if not os.path.isdir(backup):
        raise OSError(f"macOS signature backup not found: {backup}")
    with tempfile.TemporaryDirectory(prefix="agy-macos-restore-") as temp:
        _mac_write_signature_snapshot(app, temp)
        try:
            _mac_restore_signature_snapshot(backup, app)
            _mac_codesign_verify(app, bundle=True)
        except Exception:
            _mac_restore_signature_snapshot(temp, app)
            raise


def _mac_codesign_verify(path, bundle=False):
    args = ["/usr/bin/codesign", "--verify"]
    if bundle:
        args.append("--deep")
    args += ["--strict", "--verbose=2", path]
    _mac_command(args)


def _mac_xattr(action, path, attribute=None, value=None):
    """Use Python xattr APIs when available, otherwise the macOS system tool."""
    native = getattr(os, action + "xattr", None)
    if native is not None:
        args = [path]
        if attribute is not None:
            args.append(attribute)
        if value is not None:
            args.append(value)
        return native(*args, follow_symlinks=False)
    # Hex transport preserves arbitrary bytes for rollback; -s never follows links.
    args = ["/usr/bin/xattr", "-s"]
    if action == "get":
        args += ["-p", "-x", attribute]
    elif action == "remove":
        args += ["-d", attribute]
    elif action == "set":
        args += ["-w", "-x", attribute, value.hex()]
    elif action != "list":
        raise ValueError("unsupported xattr operation")
    result = _mac_command(args + [os.path.abspath(path)])
    if action == "list":
        return result.stdout.splitlines()
    if action == "get":
        return bytes.fromhex(result.stdout)


def _mac_remove_quarantine(entries):
    roots = []
    for path in entries.values():
        root = _mac_app_bundle(path) or os.path.realpath(path)
        if root not in roots:
            roots.append(root)
    attribute = "com.apple.quarantine"
    found = []
    counts = {root: 0 for root in roots}

    def walk_error(error):
        raise error

    for root in roots:
        candidates = [root]
        if root.endswith(".app"):
            for base, dirs, files in os.walk(root, onerror=walk_error, followlinks=False):
                candidates += [os.path.join(base, name) for name in dirs + files
                               if not os.path.islink(os.path.join(base, name))]
        for path in candidates:
            attrs = _mac_xattr("list", path)
            if attribute in attrs:
                found.append((root, path, _mac_xattr("get", path, attribute)))

    removed = []
    try:
        for root, path, value in found:
            _mac_xattr("remove", path, attribute)
            removed.append((path, value))
            counts[root] += 1
    except Exception:
        restore_errors = []
        for path, value in reversed(removed):
            try:
                _mac_xattr("set", path, attribute, value)
            except Exception as e:
                restore_errors.append(str(e))
        if restore_errors:
            raise OSError("quarantine removal failed and could not be rolled back: " +
                          "; ".join(restore_errors))
        raise
    for root, count in counts.items():
        if count:
            ok(f"quarantine removed from {os.path.basename(root)} ({count} item(s))")

def resolve(target, override):
    if override: return override if os.path.exists(override) else None
    for p in SPEC[target]["find"]():
        if p and os.path.exists(p): return p
    return None


def _mac_prepare_apps(paths, signing_entitlements=None, disable_library_validation=False):
    failures = {}
    seen = set()
    for path in paths.values():
        if not path:
            continue
        app = _mac_app_bundle(path)
        if not app or app in seen:
            continue
        seen.add(app)
        try:
            entitlements = None
            if signing_entitlements is not None:
                entitlements = _mac_library_validation_entitlements(app, disable_library_validation)
            _mac_prepare_signature_backup(app)
            if entitlements is not None:
                signing_entitlements[app] = entitlements
        except Exception as e:
            failures[app] = str(e)
    return failures


def _mac_run_patch(targets, overrides, disable_library_validation=False):
    rc = 0
    paths = {t: resolve(t, overrides.get(t)) for t in targets}
    signing_entitlements = {}
    app_failures = _mac_prepare_apps(paths, signing_entitlements, disable_library_validation)
    successful = {}
    changed = []
    for t in targets:
        spec = SPEC[t]; path = paths[t]
        print(f"\n=== {spec['name']} ({t}) ===")
        if not path:
            warn("not found (use --path-%s to point at it)" % t); continue
        print(f"  target: {path}")
        app = _mac_app_bundle(path)
        if app in app_failures:
            warn(f"macOS signing preparation failed: {app_failures[app]}")
            rc = 1; continue
        try:
            before = spec["status"](path)[0]
            if not spec["patch"](path):
                rc = 1; continue
            successful[t] = path
            if before == "unpatched" and spec["status"](path)[0] == "patched":
                changed.append((t, path))
        except Exception as e:
            warn(f"error: {e}"); rc = 1

    if successful:
        try:
            if signing_entitlements:
                _mac_sign_transaction(successful, bundle_entitlements=signing_entitlements)
            else:
                _mac_sign_transaction(successful)
        except Exception as e:
            warn(f"macOS code signing failed: {e}")
            for target, path in reversed(changed):
                if not restore_file(path, SPEC[target]["status"]):
                    warn(f"automatic rollback failed for {path}")
            return 1
        try:
            _mac_remove_quarantine(successful)
        except Exception as e:
            warn(f"couldn't remove macOS quarantine: {e}"); rc = 1
    return rc


def _mac_is_isolated_profile(app):
    with open(os.path.join(app, "Contents", "Info.plist"), "rb") as f:
        return plistlib.load(f).get("CFBundleIdentifier", "").startswith(
            "com.parsa.agy-profile.")


def _mac_run_restore(targets, overrides):
    with tempfile.TemporaryDirectory(prefix="agy-profile-restore-") as temp:
        return _mac_run_restore_impl(targets, overrides, temp)


def _mac_run_restore_impl(targets, overrides, temp):
    rc = 0
    paths = {t: resolve(t, overrides.get(t)) for t in targets}
    app_failures = _mac_prepare_apps(paths)
    profiles = {}
    for path in paths.values():
        app = _mac_app_bundle(path) if path else None
        if app and app not in app_failures and app not in profiles:
            try:
                profiles[app] = _mac_is_isolated_profile(app)
            except Exception as e:
                app_failures[app] = str(e)
    restored = {}
    previous = {}
    touched_apps = []
    for t in targets:
        spec = SPEC[t]; path = paths[t]
        print(f"\n=== {spec['name']} ({t}) ===")
        if not path:
            warn("not found (use --path-%s to point at it)" % t); continue
        print(f"  target: {path}")
        app = _mac_app_bundle(path)
        if app in app_failures:
            warn(f"macOS signature backup failed: {app_failures[app]}")
            rc = 1; continue
        try:
            if spec["status"](path)[0] == "patched":
                if profiles.get(app):
                    saved = os.path.join(temp, str(len(previous)))
                    _copy_binary(path, saved)
                    previous[path] = saved
                if not restore_file(path, spec["status"]):
                    rc = 1; continue
                if app and app not in touched_apps:
                    touched_apps.append(app)
                if app:
                    restored.setdefault(app, {})[t] = path
            else:
                warn("not patched — skipping restore (backup may be a different build)")
        except Exception as e:
            warn(f"error: {e}"); rc = 1

    for app in touched_apps:
        states = _mac_bundle_patch_states(app)
        remaining = {target: path for target, (state, path) in states.items()
                     if state == "patched"}
        try:
            if profiles.get(app):
                # A copied profile has its own locally signed backend, ASAR
                # and helpers. Its pre-restore seal describes patched bytes;
                # sign the restored files and reseal, even on partial restore.
                _mac_sign_transaction({**remaining, **restored[app]})
            elif remaining:
                _mac_sign_transaction(remaining)
            else:
                _mac_restore_bundle_signature(app)
                ok(f"original signature restored for {os.path.basename(app)}")
        except Exception as e:
            warn(f"macOS signature restore failed: {e}"); rc = 1
            if profiles.get(app):
                # Signing restores its signature snapshots on failure. Put
                # the original binaries back too so their seal matches and
                # the profile stays runnable and the restore can be retried.
                for path in reversed(list(restored[app].values())):
                    try:
                        _copy_binary(previous[path], path)
                    except Exception as rollback:
                        warn(f"profile restore rollback failed: {rollback}")
                        recovery = tempfile.mkdtemp(prefix=".restore-recovery-", dir=os.path.dirname(app))
                        saved = os.path.join(recovery, os.path.basename(path))
                        os.replace(previous[path], saved)
                        warn(f"original profile binary retained at {saved}")
    return rc


def run(action, targets, overrides, macos_disable_library_validation=False):
    if sys.platform == "darwin" and action == "patch":
        if macos_disable_library_validation:
            return _mac_run_patch(targets, overrides, disable_library_validation=True)
        return _mac_run_patch(targets, overrides)
    if sys.platform == "darwin" and action == "restore":
        return _mac_run_restore(targets, overrides)
    rc = 0
    for t in targets:
        spec = SPEC[t]; path = resolve(t, overrides.get(t))
        print(f"\n=== {spec['name']} ({t}) ===")
        if not path:
            warn("not found (use --path-%s to point at it)" % t); continue
        print(f"  target: {path}")
        try:
            if action == "status":
                st, _ = spec["status"](path); ok(f"status: {st}")
            elif action == "patch":
                if not spec["patch"](path): rc = 1
            elif action == "restore":
                if spec["status"](path)[0] == "patched":
                    if not restore_file(path, spec["status"]): rc = 1
                else:
                    warn("not patched — skipping restore (backup may be a different build)")
        except Exception as e:
            warn(f"error: {e}"); rc = 1
    return rc

def _status_of(t, path):
    if not path: return "not found"
    try:
        return SPEC[t]["status"](path)[0]
    except Exception:
        return "error"

def state(t, overrides=None):
    path = resolve(t, (overrides or {}).get(t))
    return path, _status_of(t, path)

def scan(overrides):
    """Resolve and scan all targets concurrently."""
    _reg_install_dirs.cache_clear(); _roots.cache_clear()
    _roots()
    def one(t):
        p = resolve(t, overrides.get(t))
        return t, p, _status_of(t, p)
    paths, status = {}, {}
    with ThreadPoolExecutor(max_workers=len(TARGETS)) as ex:
        for t, p, st in ex.map(one, TARGETS):
            paths[t], status[t] = p, st
    return paths, status

# Interactive UI
_STYLE = {"patched": "bold green", "unpatched": "yellow", "unknown": "magenta",
          "not found": "dim", "error": "bold red"}
_ICON  = {"patched": "✓", "unpatched": "●", "unknown": "?", "not found": "·", "error": "!"}

def _render(console, paths, status):
    from rich.table import Table
    from rich.panel import Panel

    tbl = Table(box=None, expand=True, pad_edge=False)
    tbl.add_column("App", style="bold cyan", no_wrap=True)
    tbl.add_column("Status", no_wrap=True)
    tbl.add_column("Location", style="dim", no_wrap=True, overflow="ellipsis", ratio=1)

    for t in ("cli", "manager", "extension", "ide"):
        path, st = paths[t], status[t]
        tbl.add_row(SPEC[t]["name"], f"[{_STYLE[st]}]{_ICON[st]} {st}[/]", path or "?")

    console.print(Panel(tbl, title="[bold white]agy-manager[/] ? Antigravity environment manager",
                        subtitle="[dim]?? move ? enter select ? space toggle[/]", border_style="cyan"))


class _TuiSessionOutput:
    """The interactive session owns the alternate screen, not each question."""
    def __init__(self, output):
        self.output = output

    def __getattr__(self, name):
        return getattr(self.output, name)

    def enter_alternate_screen(self):
        pass

    def quit_alternate_screen(self):
        pass


class _TuiDisplay:
    """Retain Rich renderables; prompt_toolkit owns the screen while asking."""
    def __init__(self, console, output=None):
        import threading
        self.console = console
        self.output = output
        self.items = []
        self._cache = None
        self.follow_tail = False
        self._revision = 0
        self._lock = threading.RLock()

    def print(self, *objects, **kwargs):
        with self._lock:
            self.items.append((objects, kwargs))
            self._revision += 1
            self._cache = None

    def rule(self, title="", **kwargs):
        from rich.rule import Rule
        self.print(Rule(title, **kwargs))

    def clear(self):
        with self._lock:
            self.items.clear()
            self._revision += 1
            self._cache = None
            self.follow_tail = False

    def formatted(self, width):
        import io
        from rich.console import Console
        from prompt_toolkit.formatted_text import ANSI, to_formatted_text
        with self._lock:
            if self._cache is not None and self._cache[0] == width:
                return self._cache[1]
            items, revision = list(self.items), self._revision
        buffer = io.StringIO()
        # Set both dimensions: Rich otherwise ignores an explicit width
        # when the parent process declares TERM=dumb.
        renderer = Console(file=buffer, width=max(1, width), height=self.console.height, force_terminal=True,
                           color_system="truecolor", legacy_windows=False)
        for objects, kwargs in items:
            renderer.print(*objects, **kwargs)
        text = to_formatted_text(ANSI(buffer.getvalue().rstrip("\n")))
        with self._lock:
            if self._revision == revision:
                self._cache = width, text
        return text


def _tui_ask(console, question, operations=None):
    operations = operations or {}
    if not isinstance(console, _TuiDisplay):
        answer = question.ask()
        if operations and answer in operations:
            message, callback = operations[answer]
            with console.status(message): callback()
        return answer
    import asyncio
    from prompt_toolkit.formatted_text import fragment_list_to_text
    from prompt_toolkit.data_structures import Point
    from prompt_toolkit.filters import Condition
    from prompt_toolkit.key_binding import ConditionalKeyBindings, KeyBindings, merge_key_bindings
    from prompt_toolkit.layout import ConditionalContainer, HSplit, Layout, Window
    from prompt_toolkit.layout.controls import FormattedTextControl
    from prompt_toolkit.layout.dimension import Dimension
    app = question.application
    if console.output is not None:
        app.output = app.renderer.output = console.output
    menu = app.layout.container
    focus = app.layout.current_control
    scroll = None
    loading = {}

    def header_text():
        return console.formatted(app.output.get_size().columns)

    def menu_height():
        if loading:
            return 1
        size = app.output.get_size()
        return min(size.rows, menu.preferred_height(size.columns, size.rows).preferred)

    def header_metrics():
        text = fragment_list_to_text(header_text())
        lines = text.count("\n") + 1 if text else 0
        available = max(0, app.output.get_size().rows - menu_height())
        hint = int(lines > available and available > 1)
        return lines, min(lines, available - hint), hint

    def scroll_position():
        lines, height, _ = header_metrics()
        limit = max(0, lines - height)
        return min(limit, max(0, scroll)) if scroll is not None else limit if console.follow_tail else 0

    bindings = KeyBindings()

    @bindings.add("c-c", eager=True)
    def cancel(event):
        event.app.exit(exception=KeyboardInterrupt)

    @bindings.add("<any>", filter=Condition(lambda: bool(loading)))
    def ignore_while_loading(event):
        pass

    @bindings.add("pageup")
    @bindings.add("pagedown")
    def scroll_header(event):
        nonlocal scroll
        step = max(1, header_metrics()[1] - 1)
        scroll = scroll_position() + (-step if event.key_sequence[0].key == "pageup" else step)

    header = FormattedTextControl(header_text, show_cursor=False,
                                 get_cursor_position=lambda: Point(0, scroll_position()))
    indicator = FormattedTextControl(
        lambda: loading["display"].formatted(app.output.get_size().columns) if loading else [],
        focusable=True, show_cursor=False)

    app.layout = Layout(HSplit([
        Window(header, height=lambda: Dimension.exact(header_metrics()[1]),
               get_vertical_scroll=lambda _: scroll_position(), always_hide_cursor=True),
        Window(FormattedTextControl("PgUp/PgDn: scroll tables and results", style="class:instruction"),
               height=lambda: Dimension.exact(header_metrics()[2])),
        ConditionalContainer(HSplit([menu], height=lambda: Dimension.exact(menu_height())),
                             filter=Condition(lambda: not loading)),
        ConditionalContainer(Window(indicator, height=1, always_hide_cursor=True),
                             filter=Condition(lambda: bool(loading))),
        Window(),
    ]), focused_element=focus)
    app.full_screen = app.renderer.full_screen = True
    app.key_bindings = merge_key_bindings([
        ConditionalKeyBindings(app.key_bindings, filter=Condition(lambda: not loading)), bindings])
    app.min_redraw_interval = .03
    app.terminal_size_polling_interval = .1
    exit_question = app.exit

    async def animate():
        while loading:
            loading["display"]._cache = None
            app.invalidate()
            await asyncio.sleep(.08)

    async def run_operation(answer, callback):
        try:
            await app.loop.run_in_executor(None, callback)
        except asyncio.CancelledError:
            raise
        except BaseException as error:
            exit_question(exception=error)
        else:
            if loading.get("cancelled"):
                exit_question(exception=KeyboardInterrupt)
            else:
                exit_question(result=answer)
        finally:
            loading.clear()
            app.layout.focus(focus)

    def exit_or_run(result=None, exception=None, style=""):
        if loading and (exception is KeyboardInterrupt or isinstance(exception, KeyboardInterrupt)):
            # Finish writes and their verification/rollback before closing UI.
            loading["cancelled"] = True
            return
        # Keep this application and its alternate screen alive until the
        # operation finishes, including the existing tables and resize handling.
        if operations and exception is None and result in operations:
            if not loading:
                from rich.spinner import Spinner
                message, callback = operations[result]
                spinner = _TuiDisplay(console.console)
                spinner.print(Spinner("dots", text=message, style="cyan"))
                loading["display"] = spinner
                app.layout.focus(indicator)
                app.create_background_task(animate())
                app.create_background_task(run_operation(result, callback))
            return
        exit_question(result=result, exception=exception, style=style)

    app.exit = exit_or_run
    try:
        return question.unsafe_ask()
    except KeyboardInterrupt:
        return None


@contextlib.contextmanager
def _tui_output(console):
    """Keep scriptable commands' ordinary print output in the menu screen."""
    if not isinstance(console, _TuiDisplay):
        yield
        return
    import io
    from rich.text import Text
    class LogStream(io.StringIO):
        pending = ""

        def write(self, value):
            count = super().write(value)
            self.pending += value
            if "\n" in self.pending:
                lines, self.pending = self.pending.rsplit("\n", 1)
                # Older Rich decoders discard line breaks in from_ansi().
                for line in lines.split("\n"):
                    console.print(Text.from_ansi(line))
                console.follow_tail = True
            return count

        def flush(self):
            if self.pending:
                console.print(Text.from_ansi(self.pending), end="")
                console.follow_tail = True
                self.pending = ""

    buffer = LogStream()
    try:
        with contextlib.redirect_stdout(buffer):
            yield
    finally:
        buffer.flush()


def _tui_run(console, message, callback, *args, **kwargs):
    """Run any operation inside the same UI, retaining live output and resize."""
    if not isinstance(console, _TuiDisplay):
        with console.status(message):
            return callback(*args, **kwargs)
    import questionary
    results = []

    def operation():
        with _tui_output(console):
            results.append(callback(*args, **kwargs))

    question = questionary.press_any_key_to_continue(message)
    question.application.pre_run_callables.append(lambda: question.application.exit(result="operation"))
    if _tui_ask(console, question, {"operation": (message, operation)}) is None:
        raise KeyboardInterrupt
    return results[0]


@contextlib.contextmanager
def _tui_console():
    """Keep menu output out of shell history and restore Windows console flags."""
    from rich.console import Console
    from prompt_toolkit.application import get_app_session
    restore = None
    if os.name == "nt" and sys.stdout.isatty():
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetStdHandle.argtypes = [wintypes.DWORD]
        kernel.GetStdHandle.restype = wintypes.HANDLE
        kernel.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel.GetConsoleMode.restype = wintypes.BOOL
        kernel.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.SetConsoleMode.restype = wintypes.BOOL
        handle = kernel.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = wintypes.DWORD()
        # Rich otherwise selects its legacy renderer, which ignores screen erase.
        if kernel.GetConsoleMode(handle, ctypes.byref(mode)):
            if kernel.SetConsoleMode(handle, mode.value | 0x0004):  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
                restore = kernel, handle, mode.value
    try:
        console = Console()
        output = get_app_session().output
        output.enter_alternate_screen()
        try:
            output.flush()
            yield _TuiDisplay(console, _TuiSessionOutput(output))
        finally:
            output.quit_alternate_screen()
            output.show_cursor()
            output.flush()
    finally:
        if restore is not None:
            kernel, handle, mode = restore
            kernel.SetConsoleMode(handle, mode)


def _clear_tui(console):
    if isinstance(console, _TuiDisplay):
        console.clear()
        return
    if os.name == "nt" and console.legacy_windows is True:
        # Classic consoles without VT still need an actual Win32 screen erase.
        from prompt_toolkit.shortcuts import clear
        clear()
    else:
        console.clear()


def interactive(overrides, macos_disable_library_validation=False):
    with _tui_console() as console:
        return _interactive(console, overrides, macos_disable_library_validation)


def _interactive(console, overrides, macos_disable_library_validation=False):
    import questionary
    qs = questionary.Style([("qmark", "fg:#00afff bold"), ("pointer", "fg:#00afff bold"),
                            ("highlighted", "fg:#00afff bold"), ("selected", "fg:#00ff87 bold"),
                            ("answer", "fg:#00ff87 bold")])
    paths, status = _tui_run(console, "Scanning installed apps?", scan, overrides)

    def refresh_status():
        nonlocal paths, status
        paths, status = scan(overrides)

    while True:
        _clear_tui(console)
        _render(console, paths, status)
        action = _tui_ask(console, questionary.select("What do you want to do?", style=qs, qmark="?", choices=[
            questionary.Choice("Patch app(s)", "patch"),
            questionary.Choice("Restore app(s) from backup", "restore"),
            questionary.Choice("Refresh status", "refresh"),
            questionary.Choice("Quit", "quit"),
        ]), operations={"refresh": ("Refreshing app status?", refresh_status)})
        if action in (None, "quit"):
            return 0
        if action == "refresh":
            continue
        _clear_tui(console)
        console.rule(f"[bold cyan]{action}[/]")
        opts = []
        for t in TARGETS:
            path, st = paths[t], status[t]
            if not path:
                continue
            if action == "patch" and st == "patched": continue
            if action == "restore" and st != "patched": continue
            opts.append(questionary.Choice(f"{SPEC[t]['name']}  ? {st}", value=t))
        if not opts:
            console.print(f"[yellow]Nothing to {action}.[/]")
            _tui_ask(console, questionary.press_any_key_to_continue("Enter to continue?", style=qs)); continue
        sel = _tui_ask(console, questionary.checkbox(f"Select app(s) to {action}:", choices=opts, style=qs))
        if not sel:
            continue
        def apply_action():
            run(action, sel, overrides, macos_disable_library_validation=macos_disable_library_validation)
            for t in TARGETS:
                status[t] = _status_of(t, paths[t])

        _tui_run(console, "Patching app(s)?" if action == "patch" else "Restoring app(s)?", apply_action)
        console.rule(style="dim")
        _tui_ask(console, questionary.press_any_key_to_continue("Enter to return to the menu?", style=qs))


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Manage the Antigravity environment (patch location gates and status). "
                    "Run with no arguments for the interactive menu.")
    ap.add_argument("action", choices=("menu", "status", "patch", "restore", "accounts"), nargs="?",
                    help="menu (default) | status | patch | restore (accounts command is removed for security)")
    ap.add_argument("targets", nargs="*", default=[], metavar="{" + ",".join(TARGETS) + "}",
                    help="which apps to act on (default: all)")
    for t in TARGETS: ap.add_argument(f"--path-{t}", help=f"explicit path for {t}")
    ap.add_argument("--macos-disable-library-validation", action="store_true",
                    help="allow an Electron app's main executable to load other/unsigned libraries after ad-hoc signing (macOS patch/menu only)")
    args = ap.parse_args(argv)

    if args.macos_disable_library_validation and (sys.platform != "darwin" or args.action not in (None, "menu", "patch")):
        ap.error("--macos-disable-library-validation is only available for patch/menu on macOS")

    if args.action == "accounts":
        warn("account management has been removed for security and credential safety")
        return 2

    bad = [t for t in args.targets if t not in TARGETS]
    if bad:
        ap.error(f"invalid target(s): {', '.join(bad)} (choose from: {', '.join(TARGETS)})")
    overrides = {t: getattr(args, f"path_{t}") for t in TARGETS}

    if args.action in (None, "menu"):
        try:
            import questionary, rich  # noqa: F401
            from prompt_toolkit import VERSION as toolkit_version
            if tuple(map(int, toolkit_version[:3])) < (3, 0, 34):
                raise ImportError("interactive menu requires prompt-toolkit >= 3.0.34")
            if not (sys.stdin.isatty() and sys.stdout.isatty()):
                raise RuntimeError("not a terminal")
            return interactive(overrides, macos_disable_library_validation=args.macos_disable_library_validation)
        except KeyboardInterrupt:
            print(); return 0
        except ImportError:
            warn('interactive menu needs:  pip install rich questionary "prompt-toolkit>=3.0.34,<4"')
            if args.action == "menu": return 2
        except Exception:
            if args.action == "menu":
                warn("interactive menu needs a real terminal"); return 2
        print("agy-manager - status")
        return run("status", list(TARGETS), overrides)

    targets = args.targets if args.targets else list(TARGETS)
    print(f"agy-manager - {args.action}")
    return run(args.action, targets, overrides, macos_disable_library_validation=args.macos_disable_library_validation)

if __name__ == "__main__":
    raise SystemExit(main())
