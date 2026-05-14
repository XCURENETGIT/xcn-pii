from __future__ import annotations

from pathlib import Path

from Cython.Build import cythonize
from setuptools import Extension, setup


APP_DIR = Path(__file__).resolve().parent / "app"

EXCLUDED_FILES = {
    "__init__.py",
    "main.py",
    "grpc_server.py",
    "context_debug_api.py",
    "guardrail.py",
    "schemas.py",
}

EXCLUDED_DIRS = {
    "proto",
    "rules",
    "static",
    "__pycache__",
}


def build_extensions() -> list[Extension]:
    extensions: list[Extension] = []
    for py_file in APP_DIR.rglob("*.py"):
        rel = py_file.relative_to(APP_DIR)
        if py_file.name in EXCLUDED_FILES or py_file.name.startswith("test_"):
            continue
        if any(part in EXCLUDED_DIRS for part in rel.parts):
            continue

        module_parts = ("app", *rel.with_suffix("").parts)
        module_name = ".".join(module_parts)
        extensions.append(Extension(module_name, [str(py_file)]))
    return extensions


setup(
    name="xcn-pii-full",
    ext_modules=cythonize(
        build_extensions(),
        compiler_directives={"language_level": "3"},
        annotate=False,
    ),
    zip_safe=False,
)
