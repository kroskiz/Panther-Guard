import hashlib
import json
import os
import subprocess
from functools import lru_cache
from pathlib import Path

# Avoid spending scan time hashing unusually large executables.
MAX_HASH_SIZE_BYTES = 100 * 1024 * 1024

_SIGNATURE_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$paths = [Console]::In.ReadToEnd() | ConvertFrom-Json
$results = foreach ($path in $paths) {
    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
        $status = [string]$signature.Status
        $signer = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
        [pscustomobject]@{ path = $path; status = $status; signer = $signer; error = $null }
    } catch {
        [pscustomobject]@{ path = $path; status = 'Unavailable'; signer = $null; error = $_.Exception.Message }
    }
}
ConvertTo-Json -InputObject @($results) -Compress
"""


def _path_key(path: str) -> str:
    return os.path.normcase(os.path.normpath(path))


def _hash_file(path: str) -> tuple[str | None, str]:
    try:
        file_path = Path(path)
        if not file_path.is_file():
            return None, "unavailable"
        file_stat = file_path.stat()
        return _hash_file_cached(path, file_stat.st_mtime_ns, file_stat.st_size)
    except OSError:
        return None, "unavailable"


@lru_cache(maxsize=512)
def _hash_file_cached(path: str, modified_ns: int, size: int) -> tuple[str | None, str]:
    if size > MAX_HASH_SIZE_BYTES:
        return None, "too_large"

    digest = hashlib.sha256()
    with Path(path).open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest(), "available"


def _inspect_signatures(paths: list[str]) -> tuple[dict[str, dict], list[str]]:
    if not paths:
        return {}, []
    path_metadata = []
    for path in sorted(set(paths), key=_path_key):
        try:
            file_stat = Path(path).stat()
            path_metadata.append((path, file_stat.st_mtime_ns, file_stat.st_size))
        except OSError:
            path_metadata.append((path, None, None))
    signatures, warnings = _inspect_signatures_cached(tuple(path_metadata))
    return {path: dict(value) for path, value in signatures.items()}, list(warnings)


@lru_cache(maxsize=16)
def _inspect_signatures_cached(
    path_metadata: tuple[tuple[str, int | None, int | None], ...],
) -> tuple[dict[str, dict], list[str]]:
    paths = [entry[0] for entry in path_metadata]
    if not paths:
        return {}, []

    # Authenticode checks use Windows PowerShell and are unavailable on other platforms.
    if os.name != "nt":
        return {}, ["Authenticode signatures are only checked on Windows."]

    environment = os.environ.copy()
    windows_directory = environment.get("WINDIR", r"C:\Windows")
    program_files = environment.get("ProgramFiles", r"C:\Program Files")
    environment["PSModulePath"] = os.pathsep.join(
        (
            str(Path(windows_directory) / "System32" / "WindowsPowerShell" / "v1.0" / "Modules"),
            str(Path(program_files) / "WindowsPowerShell" / "Modules"),
        )
    )

    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _SIGNATURE_SCRIPT],
            input=json.dumps(paths),
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
            env=environment,
        )
    except FileNotFoundError:
        return {}, ["PowerShell was not available; signature checks could not run."]
    except subprocess.TimeoutExpired:
        return {}, ["Authenticode signature checks timed out."]
    except subprocess.CalledProcessError as error:
        details = (error.stderr or error.stdout or "").strip()
        message = "Authenticode signature checks failed."
        return {}, [f"{message} {details}" if details else message]

    try:
        results = json.loads(result.stdout.lstrip("\ufeff"))
    except json.JSONDecodeError:
        return {}, ["PowerShell returned invalid signature-check data."]

    if isinstance(results, dict):
        results = [results]
    if not isinstance(results, list):
        return {}, ["PowerShell returned an unexpected signature-check format."]

    signatures = {}
    warnings = []
    recognized_statuses = {"Valid", "NotSigned", "HashMismatch", "NotTrusted"}
    for item in results:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            continue
        signature_status = str(item.get("status", "Unavailable"))
        if signature_status not in recognized_statuses:
            signature_status = "Unavailable"
        if signature_status == "Unavailable":
            error = item.get("error")
            message = f"Signature check unavailable for {Path(item['path']).name}."
            warnings.append(f"{message} {error}" if isinstance(error, str) and error else message)
        signatures[_path_key(item["path"])] = {
            "signature_status": signature_status,
            "signer": item.get("signer") if isinstance(item.get("signer"), str) else None,
        }
    return signatures, warnings


def collect_file_evidence(records: list[dict]) -> list[str]:
    """Hash and check signatures only for processes already flagged by other heuristics."""
    # Deduplicate executable paths so a shared binary is inspected only once per scan.
    candidate_paths = {
        _path_key(record["executable_path"]): record["executable_path"]
        for record in records
        if record.get("preliminary_threat_level") in {"medium", "high"}
        and isinstance(record.get("executable_path"), str)
        and record["executable_path"]
    }
    signatures, warnings = _inspect_signatures(list(candidate_paths.values()))
    file_hashes = {}

    for record in records:
        path = record.get("executable_path")
        key = _path_key(path) if isinstance(path, str) and path else None
        if key not in candidate_paths:
            # Keep skipped checks explicit instead of presenting missing evidence as a failure.
            record["file_sha256"] = None
            record["file_hash_status"] = "not_checked"
            record["signature_status"] = "not_checked"
            record["signer"] = None
            continue

        if key not in file_hashes:
            file_hashes[key] = _hash_file(path)
        record["file_sha256"], record["file_hash_status"] = file_hashes[key]
        signature = signatures.get(key)
        if signature:
            record.update(signature)
        else:
            record["signature_status"] = "Unavailable"
            record["signer"] = None

    if any(record["file_hash_status"] == "unavailable" for record in records):
        warnings.append("One or more flagged executable files could not be hashed.")
    if any(record["file_hash_status"] == "too_large" for record in records):
        warnings.append("Hashing was skipped for a flagged executable larger than 100 MiB.")
    return warnings
