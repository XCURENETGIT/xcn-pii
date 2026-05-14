from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path

from manifest_utils import (
    MANAGED_EXCLUDE_GLOBS,
    MANAGED_INCLUDE_DIRS,
    MANAGED_INCLUDE_FILES,
    MANAGED_INCLUDE_GLOBS,
    PROJECT_ROOT,
    build_file_manifest,
    collect_managed_files,
)


DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "dist" / "manifests"


def parse_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a sha256 manifest for xcn-pii managed runtime/deploy files."
    )
    parser.add_argument("--root", default=str(PROJECT_ROOT), help="Root directory to scan.")
    parser.add_argument(
        "--from-image",
        default="",
        help="Optional Docker image. When set, /app is copied from the image and scanned.",
    )
    parser.add_argument("--profile", default="", help="Optional profile label, e.g. http-cpu or grpc-cpu.")
    parser.add_argument("--version", default="", help="Optional version label.")
    parser.add_argument("--source-label", default="", help="Optional source label for audit output.")
    parser.add_argument("--base-image", default="", help="Optional base image tag/digest metadata.")
    parser.add_argument("--target-image", default="", help="Optional target image tag/digest metadata.")
    parser.add_argument("--output", default="", help="Output manifest path. Defaults under dist/manifests.")
    parser.add_argument(
        "--require-so",
        action="store_true",
        help="Fail if no compiled .so files are found.",
    )
    parser.add_argument(
        "--include-files",
        default=",".join(MANAGED_INCLUDE_FILES),
        help="Comma-separated file allowlist relative to root.",
    )
    parser.add_argument(
        "--include-dirs",
        default=",".join(MANAGED_INCLUDE_DIRS),
        help="Comma-separated directory allowlist relative to root.",
    )
    parser.add_argument(
        "--include-globs",
        default=",".join(MANAGED_INCLUDE_GLOBS),
        help="Comma-separated glob allowlist relative to root.",
    )
    parser.add_argument(
        "--exclude-globs",
        default=",".join(MANAGED_EXCLUDE_GLOBS),
        help="Comma-separated glob denylist relative to root.",
    )
    return parser.parse_args()


def extract_runtime_root(image: str, work_dir: Path) -> Path:
    runtime_root = work_dir / "runtime-root"
    container_id = subprocess.check_output(["docker", "create", image], text=True).strip()
    try:
        subprocess.run(["docker", "cp", f"{container_id}:/app", str(runtime_root)], check=True)
    finally:
        subprocess.run(["docker", "rm", "-f", container_id], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return runtime_root


def default_output_path(profile: str, version: str) -> Path:
    label = "-".join(part for part in [profile or "runtime", version] if part)
    return DEFAULT_OUTPUT_DIR / f"manifest-{label}.json"


def write_manifest(manifest: dict, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def build(args: argparse.Namespace, root: Path) -> dict:
    files = collect_managed_files(
        root,
        include_files=parse_csv(args.include_files),
        include_dirs=parse_csv(args.include_dirs),
        include_globs=parse_csv(args.include_globs),
        exclude_globs=parse_csv(args.exclude_globs),
        require_so=args.require_so,
    )
    return build_file_manifest(
        root,
        files,
        manifest_type="runtime",
        profile=args.profile,
        version=args.version,
        source_label=args.source_label,
        base_image=args.base_image,
        target_image=args.target_image,
    )


def main() -> None:
    args = parse_args()
    output_path = Path(args.output).resolve() if args.output else default_output_path(args.profile, args.version)

    if args.from_image:
        with tempfile.TemporaryDirectory(prefix="xcn-pii-manifest-") as temp_dir:
            root = extract_runtime_root(args.from_image, Path(temp_dir))
            manifest = build(args, root)
    else:
        manifest = build(args, Path(args.root).resolve())

    write_manifest(manifest, output_path)
    print(f"manifest={output_path}")
    print(f"files={len(manifest['files'])}")


if __name__ == "__main__":
    main()
