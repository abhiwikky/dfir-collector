# DFIR Collector (Windows + Linux) — Forensic Data Collection

This repository contains a **legitimate** cross-platform Python 3 forensic data collection tool intended for **incident response / DFIR** use on **Windows and Linux** hosts, executed with **Administrator/root** privileges.

It focuses on:
- **Minimal system impact** (enumeration-first; optional hashing; memory capture delegated to trusted external tools)
- **Forensic soundness** (read-only where possible; explicit logging; deterministic hashing/manifest)
- **Tamper-evident packaging** (SHA-256 of each artifact + deterministic overall bundle digest)

## What it collects

- **Memory dump (where possible)**
  - This tool **does not implement raw physical memory acquisition itself**.
  - Instead it integrates with **trusted external acquisition tools** that produce images compatible with **Volatility** (e.g., `.raw`, `.mem`, `.lime`, `AFF4`).
- **Disk metadata**
  - **Windows**: `Get-Disk`, `Get-Partition`, `Get-Volume`, `mountvol`, `wmic ...`
  - **Linux**: `lsblk -J -O`, `blkid`, `df -hT`, `/proc/mounts`, `mount`, `/etc/fstab`
- **Running processes** (via `psutil`)
  - PID, PPID, name, username, create time, command line, exe path, cwd, status
  - Optional SHA-256 of the executable (**extra IO**) via `--hash-process-exe`
- **Active network connections** (via `psutil`)
  - Local/remote IP/port, protocol (TCP/UDP), state, PID association (requires elevation)

## Bundle layout (example)

```
dfir_bundle_CASE_HOST_20260121T230700Z_ab12cd34/
  manifest.json
  logs/
    collector.ndjson
  tool/
    tool_metadata.json
    zip_metadata.json                (only if --zip)
    encryption_metadata.json         (only if --encrypt)
  host/
    host_facts.json
  process/
    processes.json
  network/
    connections.json
  disk/
    commands_summary.json
    lsblk.json / get_disk.json / ... (platform dependent)
    ... per-command outputs ...
  memory/
    memory_acquisition.json
    memory.raw                       (only if --mem-tool used and succeeds)
```

## Quick start

### Install dependencies

From the analyst/collector environment:

```bash
python -m pip install -r requirements.txt
```

### Run locally (Linux)

```bash
sudo python3 dfir_collector.py collect --output-dir /tmp --case-id IR-2026-001 --zip
```

Optional executable hashing (higher IO):

```bash
sudo python3 dfir_collector.py collect --output-dir /tmp --case-id IR-2026-001 --hash-process-exe
```

### Run locally (Windows, elevated PowerShell)

```powershell
python .\dfir_collector.py collect --output-dir C:\Windows\Temp --case-id IR-2026-001 --zip
```

## Memory acquisition (Volatility-compatible)

Memory acquisition is **environment- and policy-dependent**. Use **known-good, validated tooling** and record tool provenance/hashes.

### Windows (example: winpmem)

Download and validate `winpmem` (e.g., Magnet/Google build) per your org policy.

Example (writes into the bundle’s `memory/` directory):

```powershell
python .\dfir_collector.py collect `
  --output-dir C:\Windows\Temp `
  --case-id IR-2026-001 `
  --mem-tool C:\Tools\winpmem.exe `
  --mem-output-name memory.raw `
  --mem-args --format raw --output {out}
```

### Linux (example: AVML)

Example:

```bash
sudo python3 dfir_collector.py collect \
  --output-dir /tmp \
  --case-id IR-2026-001 \
  --mem-tool /usr/local/bin/avml \
  --mem-output-name memory.lime \
  --mem-args --output {out}
```

Notes:
- Loading kernel modules (e.g., LiME) can increase system impact; follow org policy.
- Prefer static, signed binaries from trusted sources and preserve tool hashes.

## Remote execution

### Linux via SSH (from analyst machine)

This mode uses the system `ssh`/`scp` binaries:

```bash
python3 dfir_collector.py remote-ssh \
  --ssh-host ir@10.0.0.10 \
  --case-id IR-2026-001 \
  --remote-output-dir /tmp \
  --zip \
  --scp-back-dir ./retrieved_bundles
```

### Windows via WinRM (from analyst machine)

Requires `pywinrm` and WinRM enabled on the target.

```bash
python3 dfir_collector.py remote-winrm \
  --winrm-host 10.0.0.20 \
  --winrm-user CONTOSO\\IRAdmin \
  --winrm-pass 'REDACTED' \
  --case-id IR-2026-001 \
  --zip
```

Operational notes:
- Run WinRM sessions under an administrative account.
- For transfers, prefer approved channels (SMB to a forensic share, secure copy, or winrm file transfer mechanisms).

## Safe data transfer (target → analyst)

General guidance:
- **Prefer a dedicated, access-controlled evidence share** (write-once if available).
- **Minimize additional writes** on the target. Don’t “clean up” unless policy requires it.
- **Record chain of custody**: who collected, when, host identifiers, tool versions/hashes.

### Linux transfer options

- **SCP over SSH** (simple, authenticated):

```bash
scp -r ir@10.0.0.10:/tmp/dfir_bundle_* ./evidence/
```

- **Removable media**:
  - Mount read-only where feasible on analyst side, then copy and hash-verify.

### Windows transfer options

- **Copy to a hardened UNC share** (preferred in many enterprises):
  - Example: `\\forensic-share\cases\IR-2026-001\HOST\`
- **SFTP/SCP** if available in your environment and policy allows.

## Integrity validation (tamper-evident checks)

The bundle includes `manifest.json` containing:
- SHA-256 for each file
- A deterministic `bundle_root_sha256` computed from the sorted `(path, sha256)` list

Validation steps on the analyst machine:
1. Recompute SHA-256 for each file.
2. Compare to `manifest.json`.
3. Recompute `bundle_root_sha256` the same way (or trust the tool’s output if you re-run it on the bundle).

## Volatility usage examples

Volatility expects the correct version and plugins for the image type and OS profile.

### Volatility 3 (typical)

Example commands (replace `memory.raw` with your acquired image):

```bash
vol -f memory.raw windows.info
vol -f memory.raw windows.pslist
vol -f memory.raw windows.netscan
```

Linux example:

```bash
vol -f memory.lime linux.pslist
vol -f memory.lime linux.netstat
```

## Forensic soundness notes

- **Read-only where possible**: Disk collection uses system metadata queries and does not write to disk structures.
- **Logging**: `logs/collector.ndjson` records timestamps and actions.
- **Process hashing**: Optional and can increase IO; enable only when acceptable.
- **Memory acquisition**: Uses external tools to avoid “rolling your own” kernel-level capture.

## Security + legal considerations (explicit)

- **Authorization**: Only collect from systems you are authorized to examine (warrant/consent/corporate policy).
- **Scope minimization**: Collect only what is necessary for the investigation.
- **Privacy**: Process lists and memory can contain sensitive data (credentials, PII). Handle accordingly.
- **Tool trust**: Use validated, hash-verified acquisition binaries; document versions and provenance.
- **Chain of custody**: Maintain custody logs and integrity verification evidence.

