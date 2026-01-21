"""
DFIR Collector - cross-platform forensic data collection (Windows + Linux)

Legitimate DFIR use cases only:
- No persistence
- No exploitation
- No data exfiltration beyond operator-invoked collection/transfer

This tool is designed for execution with Administrator/root privileges.
It prefers read-only access where possible and logs all actions/timestamps.

Core artifacts:
- Memory acquisition (via external, trusted acquisition tool; produces Volatility-compatible images)
- Disk metadata (partition layout, filesystem info, mounts)
- Running processes (psutil: PID, PPID, cmdline, exe path, optional SHA-256 of executable)
- Active network connections (psutil: local/remote addr, port, protocol, process association)

Remote execution support:
- Linux: via system `ssh` binary (recommended) or copy/run manually
- Windows: via WinRM (pywinrm) when available, or manual PSRemoting/WinRM invocation
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import datetime as _dt
import hashlib
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import textwrap
import time
import uuid
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import psutil


def utc_now_iso() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).isoformat()


def safe_mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def write_text(p: Path, content: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8", errors="replace")


def write_json(p: Path, obj: Any) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def relpath_posix(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


@dataclasses.dataclass(frozen=True)
class RunResult:
    cmd: List[str]
    returncode: int
    stdout: str
    stderr: str
    started_utc: str
    ended_utc: str


def run_cmd(cmd: List[str], timeout_s: int = 120, shell: bool = False) -> RunResult:
    started = utc_now_iso()
    try:
        p = subprocess.run(
            cmd if not shell else " ".join(cmd),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            shell=shell,
        )
        ended = utc_now_iso()
        return RunResult(
            cmd=cmd,
            returncode=p.returncode,
            stdout=p.stdout or "",
            stderr=p.stderr or "",
            started_utc=started,
            ended_utc=ended,
        )
    except subprocess.TimeoutExpired as e:
        ended = utc_now_iso()
        return RunResult(
            cmd=cmd,
            returncode=124,
            stdout=(e.stdout or "") if isinstance(e.stdout, str) else "",
            stderr=(e.stderr or "") if isinstance(e.stderr, str) else f"Timeout after {timeout_s}s",
            started_utc=started,
            ended_utc=ended,
        )


class CollectorLogger:
    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path
        safe_mkdir(self.log_path.parent)
        self._fh = self.log_path.open("a", encoding="utf-8", errors="replace")

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass

    def _emit(self, level: str, msg: str, **fields: Any) -> None:
        rec = {
            "ts_utc": utc_now_iso(),
            "level": level,
            "msg": msg,
            **fields,
        }
        self._fh.write(json.dumps(rec, sort_keys=True) + "\n")
        self._fh.flush()

    def info(self, msg: str, **fields: Any) -> None:
        self._emit("INFO", msg, **fields)

    def warn(self, msg: str, **fields: Any) -> None:
        self._emit("WARN", msg, **fields)

    def error(self, msg: str, **fields: Any) -> None:
        self._emit("ERROR", msg, **fields)


def is_admin_or_root() -> bool:
    if os.name == "nt":
        try:
            import ctypes  # stdlib

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def host_facts() -> Dict[str, Any]:
    return {
        "collected_utc": utc_now_iso(),
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "python": sys.version,
        "boot_time_utc": _dt.datetime.fromtimestamp(psutil.boot_time(), tz=_dt.timezone.utc).isoformat(),
        "users": [{"name": u.name, "terminal": u.terminal, "host": u.host, "started": u.started} for u in psutil.users()],
    }


def collect_processes(include_hashes: bool, logger: CollectorLogger) -> Dict[str, Any]:
    """
    Uses psutil. Hashing executables can add IO; keep optional.
    """
    out: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    for p in psutil.process_iter(attrs=["pid", "ppid", "name", "username", "create_time"]):
        try:
            info = p.info
            with p.oneshot():
                cmdline = []
                try:
                    cmdline = p.cmdline()
                except Exception:
                    cmdline = []
                exe = None
                try:
                    exe = p.exe()
                except Exception:
                    exe = None
                cwd = None
                try:
                    cwd = p.cwd()
                except Exception:
                    cwd = None
                status = None
                try:
                    status = p.status()
                except Exception:
                    status = None

            rec: Dict[str, Any] = {
                "pid": info.get("pid"),
                "ppid": info.get("ppid"),
                "name": info.get("name"),
                "username": info.get("username"),
                "create_time": info.get("create_time"),
                "cmdline": cmdline,
                "exe": exe,
                "cwd": cwd,
                "status": status,
            }

            if include_hashes and exe:
                try:
                    exe_path = Path(exe)
                    if exe_path.is_file():
                        rec["exe_sha256"] = sha256_file(exe_path)
                except Exception as e:
                    rec["exe_sha256_error"] = repr(e)

            out.append(rec)
        except Exception as e:
            errors.append({"pid": getattr(p, "pid", None), "error": repr(e)})

    logger.info("Collected processes", count=len(out), errors=len(errors))
    return {"processes": out, "errors": errors}


def _proto_name(t: int) -> str:
    if t == socket.SOCK_STREAM:
        return "tcp"
    if t == socket.SOCK_DGRAM:
        return "udp"
    return str(t)


def collect_network(logger: CollectorLogger) -> Dict[str, Any]:
    conns_out: List[Dict[str, Any]] = []
    errors: List[str] = []

    # psutil.net_connections may require elevated privileges for process association.
    try:
        conns = psutil.net_connections(kind="all")
    except Exception as e:
        logger.error("Failed net_connections", error=repr(e))
        return {"connections": [], "errors": [repr(e)]}

    for c in conns:
        try:
            laddr = None
            raddr = None
            if c.laddr:
                laddr = {"ip": c.laddr.ip if hasattr(c.laddr, "ip") else c.laddr[0], "port": c.laddr.port if hasattr(c.laddr, "port") else c.laddr[1]}
            if c.raddr:
                raddr = {"ip": c.raddr.ip if hasattr(c.raddr, "ip") else c.raddr[0], "port": c.raddr.port if hasattr(c.raddr, "port") else c.raddr[1]}
            conns_out.append(
                {
                    "fd": getattr(c, "fd", None),
                    "family": str(c.family),
                    "type": _proto_name(c.type),
                    "laddr": laddr,
                    "raddr": raddr,
                    "status": getattr(c, "status", None),
                    "pid": getattr(c, "pid", None),
                }
            )
        except Exception as e:
            errors.append(repr(e))

    logger.info("Collected network connections", count=len(conns_out), errors=len(errors))
    return {"connections": conns_out, "errors": errors}


def collect_disk_metadata_windows(logger: CollectorLogger) -> Dict[str, Any]:
    """
    Uses built-in Windows commands / PowerShell to capture disk/volume metadata read-only.
    """
    cmds = [
        (["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "Get-Disk | Select * | ConvertTo-Json -Depth 4"], "get_disk.json"),
        (["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "Get-Partition | Select * | ConvertTo-Json -Depth 4"], "get_partition.json"),
        (["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "Get-Volume | Select * | ConvertTo-Json -Depth 4"], "get_volume.json"),
        (["cmd", "/c", "mountvol"], "mountvol.txt"),
        (["cmd", "/c", "wmic logicaldisk get DeviceID,FileSystem,FreeSpace,Size,VolumeName /format:list"], "wmic_logicaldisk.txt"),
        (["cmd", "/c", "wmic partition get Name,Type,Size,StartingOffset /format:list"], "wmic_partition.txt"),
        (["cmd", "/c", "wmic diskdrive get Model,SerialNumber,Size,InterfaceType /format:list"], "wmic_diskdrive.txt"),
    ]
    results: List[Dict[str, Any]] = []
    for cmd, fname in cmds:
        rr = run_cmd(cmd, timeout_s=120)
        results.append(dataclasses.asdict(rr) | {"output_file": fname})
    logger.info("Collected Windows disk metadata", commands=len(cmds))
    return {"commands": results}


def collect_disk_metadata_linux(logger: CollectorLogger) -> Dict[str, Any]:
    """
    Uses common Linux userland tools; if a tool is missing, logs errors.
    """
    cmds = [
        (["/bin/sh", "-c", "uname -a"], "uname.txt"),
        (["/bin/sh", "-c", "lsblk -J -O"], "lsblk.json"),
        (["/bin/sh", "-c", "blkid -o full"], "blkid.txt"),
        (["/bin/sh", "-c", "df -hT"], "df.txt"),
        (["/bin/sh", "-c", "cat /proc/mounts"], "proc_mounts.txt"),
        (["/bin/sh", "-c", "mount"], "mount.txt"),
        (["/bin/sh", "-c", "cat /etc/fstab 2>/dev/null || true"], "fstab.txt"),
    ]
    results: List[Dict[str, Any]] = []
    for cmd, fname in cmds:
        rr = run_cmd(cmd, timeout_s=120)
        results.append(dataclasses.asdict(rr) | {"output_file": fname})
    logger.info("Collected Linux disk metadata", commands=len(cmds))
    return {"commands": results}


def acquire_memory_external(
    system: str,
    out_path: Path,
    tool_path: Optional[str],
    tool_args: List[str],
    logger: CollectorLogger,
) -> Dict[str, Any]:
    """
    Memory acquisition is intentionally delegated to a trusted, externally provided tool to:
    - preserve forensic soundness expectations in real-world workflows
    - produce images compatible with Volatility (e.g., .raw, .mem, AFF4)

    Examples:
    - Windows: winpmem (Magnet/Google) producing .raw or AFF4
    - Linux: AVML (Microsoft) producing .lime/.raw, or LiME kernel module (environment-specific)
    """
    if not tool_path:
        logger.warn("Memory tool not configured; skipping memory acquisition")
        return {"skipped": True, "reason": "No --mem-tool provided", "output": str(out_path)}

    tp = Path(tool_path)
    if not tp.exists():
        logger.error("Memory tool path not found", tool=str(tp))
        return {"skipped": True, "reason": "Memory tool not found", "tool": str(tp), "output": str(out_path)}

    safe_mkdir(out_path.parent)

    # Very conservative invocation patterns; caller provides args template.
    # We append output path if args contain '{out}', else append output at end.
    final_args = [a.replace("{out}", str(out_path)) for a in tool_args]
    if "{out}" not in " ".join(tool_args):
        final_args = final_args + [str(out_path)]

    cmd = [str(tp)] + final_args
    logger.info("Starting memory acquisition", tool=str(tp), cmd=cmd)

    rr = run_cmd(cmd, timeout_s=60 * 60, shell=False)  # allow long capture
    meta = dataclasses.asdict(rr)
    meta["output"] = str(out_path)
    meta["tool"] = str(tp)
    meta["system"] = system

    if rr.returncode != 0:
        logger.error("Memory acquisition failed", returncode=rr.returncode)
    else:
        logger.info("Memory acquisition completed", returncode=rr.returncode)
    return meta


def build_manifest(bundle_root: Path, logger: CollectorLogger) -> Dict[str, Any]:
    """
    Tamper-evident bundle:
    - SHA-256 for every file
    - Bundle root hash computed from sorted (path, sha256) pairs
    """
    file_hashes: List[Dict[str, str]] = []
    for p in sorted(bundle_root.rglob("*")):
        if p.is_file():
            # Don't include the manifest while computing it (written after)
            if p.name in {"manifest.json"}:
                continue
            h = sha256_file(p)
            file_hashes.append({"path": relpath_posix(p, bundle_root), "sha256": h})

    # Create deterministic overall digest
    overall_h = hashlib.sha256()
    for item in file_hashes:
        overall_h.update(item["path"].encode("utf-8"))
        overall_h.update(b"\x00")
        overall_h.update(item["sha256"].encode("ascii"))
        overall_h.update(b"\n")

    manifest = {
        "manifest_version": 1,
        "created_utc": utc_now_iso(),
        "bundle_root_sha256": overall_h.hexdigest(),
        "files": file_hashes,
    }
    logger.info("Built manifest", files=len(file_hashes))
    return manifest


def zip_bundle(bundle_root: Path, zip_path: Path, logger: CollectorLogger) -> None:
    safe_mkdir(zip_path.parent)
    logger.info("Creating zip", zip=str(zip_path))
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for p in sorted(bundle_root.rglob("*")):
            if p.is_file():
                zf.write(p, arcname=relpath_posix(p, bundle_root))


def encrypt_file_aesgcm(in_path: Path, out_path: Path, passphrase: str, logger: CollectorLogger) -> Dict[str, Any]:
    """
    Optional encryption (requires cryptography). Uses:
    - PBKDF2-HMAC-SHA256 key derivation
    - AES-256-GCM for confidentiality + integrity

    Output file format (JSON):
      {
        "kdf": {"name":"pbkdf2_hmac_sha256","salt_b64":"...","iterations":200000},
        "aead": {"name":"aes_256_gcm","nonce_b64":"..."},
        "ciphertext_b64":"..."
      }
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
    except Exception as e:
        logger.error("cryptography not available; encryption skipped", error=repr(e))
        raise

    salt = os.urandom(16)
    nonce = os.urandom(12)
    iterations = 200_000

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    key = kdf.derive(passphrase.encode("utf-8"))
    aesgcm = AESGCM(key)

    pt = in_path.read_bytes()
    ct = aesgcm.encrypt(nonce, pt, associated_data=None)

    obj = {
        "kdf": {
            "name": "pbkdf2_hmac_sha256",
            "salt_b64": base64.b64encode(salt).decode("ascii"),
            "iterations": iterations,
        },
        "aead": {"name": "aes_256_gcm", "nonce_b64": base64.b64encode(nonce).decode("ascii")},
        "ciphertext_b64": base64.b64encode(ct).decode("ascii"),
    }

    safe_mkdir(out_path.parent)
    out_path.write_text(json.dumps(obj, indent=2), encoding="utf-8")
    logger.info("Encrypted file", in_path=str(in_path), out_path=str(out_path))
    return {"encrypted": True, "out_path": str(out_path)}


def write_command_outputs(results: Dict[str, Any], out_dir: Path, logger: CollectorLogger) -> None:
    """
    Writes per-command output files and a summary JSON.
    """
    safe_mkdir(out_dir)
    for cmdrec in results.get("commands", []):
        fname = cmdrec.get("output_file")
        if not fname:
            continue
        txt = ""
        # Prefer stdout+stderr to preserve evidence of tool errors.
        txt += f"## cmd: {' '.join(cmdrec.get('cmd', []))}\n"
        txt += f"## returncode: {cmdrec.get('returncode')}\n"
        txt += f"## started_utc: {cmdrec.get('started_utc')}\n"
        txt += f"## ended_utc: {cmdrec.get('ended_utc')}\n\n"
        txt += "### stdout\n"
        txt += cmdrec.get("stdout", "")
        txt += "\n\n### stderr\n"
        txt += cmdrec.get("stderr", "")
        write_text(out_dir / fname, txt)
    write_json(out_dir / "commands_summary.json", results)
    logger.info("Wrote command outputs", dir=str(out_dir))


def make_bundle_root(out_base: Path, case_id: str) -> Path:
    ts = _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    host = socket.gethostname()
    bundle_name = f"dfir_bundle_{case_id}_{host}_{ts}_{uuid.uuid4().hex[:8]}"
    return out_base / bundle_name


def collect_local(args: argparse.Namespace) -> int:
    if args.require_admin and not is_admin_or_root():
        print("ERROR: This tool must be run as Administrator/root.", file=sys.stderr)
        return 2

    out_base = Path(args.output_dir).expanduser().resolve()
    bundle_root = make_bundle_root(out_base, args.case_id)

    layout = {
        "root": str(bundle_root),
        "dirs": {
            "logs": "logs",
            "host": "host",
            "process": "process",
            "network": "network",
            "disk": "disk",
            "memory": "memory",
            "tool": "tool",
        },
    }

    safe_mkdir(bundle_root)
    logger = CollectorLogger(bundle_root / "logs" / "collector.ndjson")
    logger.info("Collection started", bundle=str(bundle_root), system=platform.system())

    try:
        # Record tool metadata
        write_json(bundle_root / "tool" / "tool_metadata.json", {"tool": "dfir_collector.py", "version": "1.0", "argv": sys.argv, "started_utc": utc_now_iso()})
        write_json(bundle_root / "host" / "host_facts.json", host_facts())

        # Processes and network (psutil)
        proc = collect_processes(include_hashes=args.hash_process_exe, logger=logger)
        write_json(bundle_root / "process" / "processes.json", proc)

        net = collect_network(logger=logger)
        write_json(bundle_root / "network" / "connections.json", net)

        # Disk metadata (platform-specific commands)
        if platform.system().lower() == "windows":
            disk = collect_disk_metadata_windows(logger=logger)
        else:
            disk = collect_disk_metadata_linux(logger=logger)
        write_command_outputs(disk, bundle_root / "disk", logger)

        # Memory acquisition via external tool (optional)
        mem_out = bundle_root / "memory" / args.mem_output_name
        mem_meta = acquire_memory_external(
            system=platform.system(),
            out_path=mem_out,
            tool_path=args.mem_tool,
            tool_args=args.mem_args or [],
            logger=logger,
        )
        write_json(bundle_root / "memory" / "memory_acquisition.json", mem_meta)

        # Build manifest last
        manifest = build_manifest(bundle_root, logger)
        write_json(bundle_root / "manifest.json", manifest)

        # Optional packaging
        if args.zip:
            zip_path = bundle_root.with_suffix(".zip")
            zip_bundle(bundle_root, zip_path, logger)
            write_json(bundle_root / "tool" / "zip_metadata.json", {"zip_path": str(zip_path), "zip_sha256": sha256_file(zip_path)})

            if args.encrypt and args.encrypt_passphrase:
                enc_path = zip_path.with_suffix(".zip.aesgcm.json")
                encrypt_file_aesgcm(zip_path, enc_path, args.encrypt_passphrase, logger)
                write_json(bundle_root / "tool" / "encryption_metadata.json", {"encrypted_path": str(enc_path)})

        logger.info("Collection finished", bundle=str(bundle_root))
        print(str(bundle_root))
        return 0
    finally:
        logger.close()


def ssh_remote_collect(args: argparse.Namespace) -> int:
    """
    Remote execution for Linux via system ssh:
    - Copy dfir_collector.py to remote /tmp (or provided)
    - Execute with sudo
    - Optionally scp bundle back
    """
    if not args.ssh_host:
        print("ERROR: --ssh-host required", file=sys.stderr)
        return 2

    remote_path = args.remote_path or "/tmp/dfir_collector.py"
    remote_out = args.remote_output_dir or "/tmp"

    local_script = Path(__file__).resolve()
    scp = ["scp", "-q", str(local_script), f"{args.ssh_host}:{remote_path}"]
    rc = run_cmd(scp, timeout_s=300)
    if rc.returncode != 0:
        print(rc.stderr or rc.stdout, file=sys.stderr)
        return rc.returncode

    # Build remote command
    remote_cmd = [
        "ssh",
        args.ssh_host,
        "sudo",
        "python3",
        remote_path,
        "collect",
        "--output-dir",
        remote_out,
        "--case-id",
        args.case_id,
    ]
    if args.hash_process_exe:
        remote_cmd.append("--hash-process-exe")
    if args.mem_tool:
        remote_cmd += ["--mem-tool", args.mem_tool]
    if args.mem_output_name:
        remote_cmd += ["--mem-output-name", args.mem_output_name]
    if args.mem_args:
        remote_cmd += ["--mem-args"] + args.mem_args
    if args.zip:
        remote_cmd.append("--zip")

    rr = run_cmd(remote_cmd, timeout_s=60 * 60)
    if rr.returncode != 0:
        print(rr.stderr or rr.stdout, file=sys.stderr)
        return rr.returncode

    bundle_path = (rr.stdout or "").strip().splitlines()[-1].strip()
    print(bundle_path)

    if args.scp_back_dir:
        safe_mkdir(Path(args.scp_back_dir))
        pull = ["scp", "-r", f"{args.ssh_host}:{bundle_path}", str(Path(args.scp_back_dir).resolve())]
        pr = run_cmd(pull, timeout_s=60 * 60)
        if pr.returncode != 0:
            print(pr.stderr or pr.stdout, file=sys.stderr)
            return pr.returncode
    return 0


def winrm_remote_collect(args: argparse.Namespace) -> int:
    """
    Remote execution for Windows via WinRM (pywinrm):
    - Upload script content and execute in a temp directory
    - Returns remote bundle path; operator can transfer via SMB/WinRM download tooling
    """
    try:
        import winrm  # type: ignore
    except Exception as e:
        print("ERROR: pywinrm not installed; install it or use manual WinRM/PSRemoting.", file=sys.stderr)
        print(repr(e), file=sys.stderr)
        return 2

    if not args.winrm_host or not args.winrm_user or not args.winrm_pass:
        print("ERROR: --winrm-host/--winrm-user/--winrm-pass required", file=sys.stderr)
        return 2

    local_script = Path(__file__).read_text(encoding="utf-8", errors="replace")

    # Create session
    endpoint = args.winrm_endpoint or f"http://{args.winrm_host}:5985/wsman"
    s = winrm.Session(endpoint, auth=(args.winrm_user, args.winrm_pass), transport=args.winrm_transport or "ntlm")

    # Write script to remote temp (PowerShell here-string)
    remote_dir = args.remote_output_dir or r"C:\Windows\Temp"
    remote_script = str(Path(remote_dir) / "dfir_collector.py")

    ps_write = textwrap.dedent(
        f"""
        $p = "{remote_script}"
        $content = @'
{local_script}
'@
        Set-Content -Path $p -Value $content -Encoding UTF8
        Write-Output $p
        """
    )
    r1 = s.run_ps(ps_write)
    if r1.status_code != 0:
        print(r1.std_err.decode(errors="replace") if hasattr(r1.std_err, "decode") else str(r1.std_err), file=sys.stderr)
        return r1.status_code

    # Execute collection (requires admin; recommend running WinRM session under admin account)
    ps_collect = f'python "{remote_script}" collect --output-dir "{remote_dir}" --case-id "{args.case_id}"'
    if args.hash_process_exe:
        ps_collect += " --hash-process-exe"
    if args.zip:
        ps_collect += " --zip"

    r2 = s.run_cmd("powershell", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_collect])
    out = (r2.std_out.decode(errors="replace") if hasattr(r2.std_out, "decode") else str(r2.std_out)).strip()
    err = (r2.std_err.decode(errors="replace") if hasattr(r2.std_err, "decode") else str(r2.std_err)).strip()
    if r2.status_code != 0:
        print(err or out, file=sys.stderr)
        return r2.status_code

    # Expected last line is bundle path
    bundle_path = out.splitlines()[-1].strip() if out else ""
    print(bundle_path)
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Cross-platform DFIR forensic data collection (Windows/Linux).")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("collect", help="Collect artifacts locally (run as admin/root).")
    c.add_argument("--output-dir", required=True, help="Directory where the bundle folder will be created.")
    c.add_argument("--case-id", default="CASE", help="Case identifier included in bundle name.")
    c.add_argument(
        "--require-admin",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Fail if not admin/root (default: true). Use --no-require-admin to override for testing.",
    )
    c.add_argument("--hash-process-exe", action="store_true", help="Compute SHA-256 of process executable paths (extra IO).")
    c.add_argument("--mem-tool", default=None, help="Path to external memory acquisition tool (winpmem/avml/etc).")
    c.add_argument("--mem-output-name", default="memory.raw", help="Memory output filename inside bundle (default: memory.raw).")
    c.add_argument("--mem-args", nargs=argparse.REMAINDER, help="Arguments for --mem-tool. Use {out} for output placeholder.")
    c.add_argument("--zip", action="store_true", help="Also create a .zip of the bundle directory.")
    c.add_argument("--encrypt", action="store_true", help="Encrypt the zip using AES-GCM (requires cryptography).")
    c.add_argument("--encrypt-passphrase", default=None, help="Passphrase for encryption (prefer passing via environment/secure prompt).")
    c.set_defaults(func=collect_local)

    r = sub.add_parser("remote-ssh", help="Execute collection remotely on Linux via SSH.")
    r.add_argument("--ssh-host", required=True, help="SSH target, e.g. user@host.")
    r.add_argument("--remote-path", default=None, help="Remote path for script (default: /tmp/dfir_collector.py).")
    r.add_argument("--remote-output-dir", default=None, help="Remote output dir for bundle (default: /tmp).")
    r.add_argument("--scp-back-dir", default=None, help="If set, scp the bundle back into this local directory.")
    r.add_argument("--case-id", default="CASE", help="Case identifier.")
    r.add_argument("--hash-process-exe", action="store_true")
    r.add_argument("--mem-tool", default=None)
    r.add_argument("--mem-output-name", default="memory.raw")
    r.add_argument("--mem-args", nargs=argparse.REMAINDER)
    r.add_argument("--zip", action="store_true")
    r.set_defaults(func=ssh_remote_collect)

    w = sub.add_parser("remote-winrm", help="Execute collection remotely on Windows via WinRM (pywinrm).")
    w.add_argument("--winrm-host", required=True, help="Windows host (IP/DNS).")
    w.add_argument("--winrm-endpoint", default=None, help="WinRM endpoint URL (default http://host:5985/wsman).")
    w.add_argument("--winrm-transport", default=None, help="pywinrm transport (default ntlm).")
    w.add_argument("--winrm-user", required=True)
    w.add_argument("--winrm-pass", required=True)
    w.add_argument("--remote-output-dir", default=None, help="Remote output directory (default C:\\Windows\\Temp).")
    w.add_argument("--case-id", default="CASE")
    w.add_argument("--hash-process-exe", action="store_true")
    w.add_argument("--zip", action="store_true")
    w.set_defaults(func=winrm_remote_collect)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())

