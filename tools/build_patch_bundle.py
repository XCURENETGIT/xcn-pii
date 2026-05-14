from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from manifest_utils import load_manifest, manifest_files_by_path, sha256_file


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_APP_DIR = PROJECT_ROOT / "app"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "dist" / "patches"
DEFAULT_INCLUDE_FILES = [
    "VERSION",
    "app/__init__.py",
    "app/main.py",
    "app/grpc_server.py",
    "app/context_debug_api.py",
    "app/guardrail.py",
    "app/schemas.py",
]
DEFAULT_INCLUDE_DIRS = [
    "app/proto",
    "app/rules",
    "app/static",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a runtime patch bundle containing compiled .so files and required runtime files."
    )
    parser.add_argument("--profile", choices=["http-cpu", "grpc-cpu"], required=True)
    parser.add_argument(
        "--version",
        default="",
        help="Patch version label. Defaults to the first line of VERSION.",
    )
    parser.add_argument("--app-dir", default=str(DEFAULT_APP_DIR))
    parser.add_argument(
        "--from-image",
        default="",
        help="Optional built runtime image to extract /app from. Use this after Docker build when .so files exist only inside the image.",
    )
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument(
        "--base-image",
        default="",
        help="Optional base image tag or digest for compatibility metadata.",
    )
    parser.add_argument(
        "--target-image",
        default="",
        help="Optional patched image tag for compatibility metadata.",
    )
    parser.add_argument(
        "--bundle-name",
        default="",
        help="Optional custom bundle directory/file name. Defaults to patch-<profile>-<version>.",
    )
    parser.add_argument(
        "--base-manifest",
        default="",
        help="Optional manifest from the base runtime/package. Adds before_sha256 preflight checks.",
    )
    return parser.parse_args()


def copy_file(src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)


def read_version(source_root: Path) -> str:
    version_path = source_root / "VERSION"
    if not version_path.is_file():
        raise FileNotFoundError(f"VERSION file is missing: {version_path}")
    version = version_path.read_text(encoding="utf-8").splitlines()[0].strip()
    if not version:
        raise ValueError("VERSION file is empty")
    return version


def get_git_sha() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return ""
    return result.stdout.strip()


def extract_runtime_root(image: str, work_dir: Path) -> Path:
    runtime_root = work_dir / "runtime-root"
    container_id = subprocess.check_output(["docker", "create", image], text=True).strip()
    try:
        subprocess.run(["docker", "cp", f"{container_id}:/app", str(runtime_root)], check=True)
    finally:
        subprocess.run(["docker", "rm", "-f", container_id], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return runtime_root


def collect_runtime_files(source_root: Path, app_dir: Path) -> list[Path]:
    files: list[Path] = []

    for relative in DEFAULT_INCLUDE_FILES:
        path = source_root / relative
        if path.exists():
            files.append(path)

    for relative in DEFAULT_INCLUDE_DIRS:
        root = source_root / relative
        if root.exists():
            files.extend(sorted(path for path in root.rglob("*") if path.is_file()))

    bin_dir = source_root / "bin"
    if bin_dir.exists():
        files.extend(sorted(path for path in bin_dir.rglob("*") if path.is_file()))

    so_files = sorted(path for path in app_dir.rglob("*.so") if path.is_file())
    if not so_files:
        raise FileNotFoundError(
            f"No compiled .so files found in {app_dir}. Build extensions first."
        )
    files.extend(so_files)

    unique_files: list[Path] = []
    seen: set[Path] = set()
    for path in files:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        unique_files.append(path)
    return unique_files


def build_manifest(
    source_root: Path,
    bundle_name: str,
    profile: str,
    version: str,
    base_image: str,
    target_image: str,
    files: list[Path],
    base_manifest: dict | None = None,
) -> dict:
    manifest_files = []
    base_files = manifest_files_by_path(base_manifest or {})
    for path in sorted(files):
        relative_path = path.relative_to(source_root).as_posix()
        after_sha256 = sha256_file(path)
        base_entry = base_files.get(relative_path)
        before_sha256 = str(base_entry.get("sha256", "")) if base_entry else ""
        if not before_sha256:
            action = "add"
        elif before_sha256 == after_sha256:
            action = "unchanged"
        else:
            action = "modify"
        manifest_files.append(
            {
                "path": relative_path,
                "action": action,
                "size": path.stat().st_size,
                "mode": oct(path.stat().st_mode & 0o777),
                "before_sha256": before_sha256,
                "after_sha256": after_sha256,
                "sha256": after_sha256,
            }
        )

    change_summary = {
        "add": sum(1 for entry in manifest_files if entry["action"] == "add"),
        "modify": sum(1 for entry in manifest_files if entry["action"] == "modify"),
        "unchanged": sum(1 for entry in manifest_files if entry["action"] == "unchanged"),
    }

    return {
        "schema_version": 2,
        "manifest_type": "patch",
        "bundle_name": bundle_name,
        "profile": profile,
        "version": version,
        "created_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "git_sha": get_git_sha(),
        "python_version": os.sys.version.split()[0],
        "base_image": base_image,
        "target_image": target_image,
        "preflight_required": bool(base_manifest),
        "change_summary": change_summary,
        "base_manifest": {
            "source_label": (base_manifest or {}).get("source_label", ""),
            "profile": (base_manifest or {}).get("profile", ""),
            "version": (base_manifest or {}).get("version", ""),
            "created_at_utc": (base_manifest or {}).get("created_at_utc", ""),
            "git_sha": (base_manifest or {}).get("git_sha", ""),
        } if base_manifest else None,
        "files": manifest_files,
    }


def write_bundle(source_root: Path, output_dir: Path, manifest: dict, runtime_files: list[Path]) -> Path:
    bundle_name = manifest["bundle_name"]
    bundle_root = output_dir / manifest["profile"] / bundle_name
    if bundle_root.exists():
        shutil.rmtree(bundle_root)
    payload_root = bundle_root / "payload"
    payload_root.mkdir(parents=True, exist_ok=True)

    for src in runtime_files:
        relative = src.relative_to(source_root)
        copy_file(src, payload_root / relative)

    copy_file(PROJECT_ROOT / "scripts" / "apply_runtime_patch.sh", bundle_root / "apply_runtime_patch.sh")
    copy_file(PROJECT_ROOT / "scripts" / "build_patched_image.sh", bundle_root / "build_patched_image.sh")

    manifest_path = bundle_root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")

    archive_path = bundle_root.with_suffix(".tar.gz")
    if archive_path.exists():
        archive_path.unlink()
    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(bundle_root, arcname=bundle_root.name)
    return archive_path


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir).resolve()
    base_manifest = load_manifest(Path(args.base_manifest).resolve()) if args.base_manifest else None

    with tempfile.TemporaryDirectory(prefix="xcn-pii-patch-") as temp_dir:
        source_root = PROJECT_ROOT
        app_dir = Path(args.app_dir).resolve()
        if args.from_image:
            source_root = extract_runtime_root(args.from_image, Path(temp_dir))
            app_dir = source_root / "app"

        version = args.version or read_version(source_root)
        bundle_name = args.bundle_name or f"patch-{args.profile}-{version}"
        runtime_files = collect_runtime_files(source_root, app_dir)
        manifest = build_manifest(
            source_root,
            bundle_name,
            args.profile,
            version,
            args.base_image,
            args.target_image,
            runtime_files,
            base_manifest,
        )
        archive_path = write_bundle(source_root, output_dir, manifest, runtime_files)

    print(f"bundle_dir={archive_path.with_suffix('').with_suffix('')}")
    print(f"bundle_archive={archive_path}")


if __name__ == "__main__":
    main()
