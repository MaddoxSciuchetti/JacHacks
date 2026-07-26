"""Lazy CodeBERT inference service used by the Jac server endpoint."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import replace
from pathlib import Path
from types import ModuleType
from typing import Any
from urllib.parse import urlparse


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_PIPELINE_FILE = (
    PROJECT_ROOT
    / "artifacts"
    / "jac_codebert_pipeline_bundle"
    / "jac_codebert_pipeline.py"
)
DEFAULT_MODEL_DIR = PROJECT_ROOT / "runs" / "jac-codebert"
GITHUB_SEGMENT = re.compile(r"^[A-Za-z0-9_.-]+$")

TYPE_TITLES = {
    "CODE_INJECTION": "Code injection",
    "CROSS_SITE_SCRIPTING": "Cross-site scripting",
    "HARDCODED_SECRET": "Hardcoded secret",
    "MISSING_AUTHENTICATION": "Missing authentication",
    "OS_COMMAND_INJECTION": "OS command injection",
    "PATH_TRAVERSAL": "Path traversal",
    "PREDICTABLE_TOKEN": "Predictable security token",
    "SERVER_SIDE_REQUEST_FORGERY": "Server-side request forgery",
    "SQL_INJECTION": "SQL injection",
    "UNSAFE_DESERIALIZATION": "Unsafe deserialization",
}
HIGH_SEVERITY = {
    "CODE_INJECTION",
    "HARDCODED_SECRET",
    "OS_COMMAND_INJECTION",
    "SERVER_SIDE_REQUEST_FORGERY",
    "SQL_INJECTION",
    "UNSAFE_DESERIALIZATION",
}

_RUNTIME_LOCK = threading.Lock()
_RUNTIME_CACHE: dict[str, Any] | None = None


def _positive_int(name: str, default: int) -> int:
    value = int(os.getenv(name, str(default)))
    if value <= 0:
        raise RuntimeError(f"{name} must be greater than zero.")
    return value


def _threshold() -> float:
    value = float(os.getenv("JAC_SCAN_THRESHOLD", "0.60"))
    if not 0.0 < value < 1.0:
        raise RuntimeError("JAC_SCAN_THRESHOLD must be between zero and one.")
    return value


def _canonical_github_url(repository: str) -> str:
    parsed = urlparse(repository.strip())
    if (
        parsed.scheme != "https"
        or (parsed.hostname or "").lower() != "github.com"
        or parsed.username
        or parsed.password
        or parsed.port
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "Enter a public GitHub HTTPS URL such as "
            "https://github.com/owner/repository."
        )

    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 2:
        raise ValueError("The GitHub URL must contain one owner and repository.")
    owner = parts[0]
    repo = parts[1][:-4] if parts[1].endswith(".git") else parts[1]
    if (
        not owner
        or not repo
        or not GITHUB_SEGMENT.fullmatch(owner)
        or not GITHUB_SEGMENT.fullmatch(repo)
    ):
        raise ValueError("The GitHub owner or repository name is invalid.")
    return f"https://github.com/{owner}/{repo}.git"


def _load_pipeline(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "jac_codebert_runtime_pipeline",
        path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load the model pipeline: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _runtime() -> dict[str, Any]:
    global _RUNTIME_CACHE
    if _RUNTIME_CACHE is not None:
        return _RUNTIME_CACHE

    pipeline_file = Path(
        os.getenv("JAC_PIPELINE_FILE", str(DEFAULT_PIPELINE_FILE))
    ).expanduser().resolve()
    model_dir = Path(
        os.getenv("JAC_MODEL_DIR", str(DEFAULT_MODEL_DIR))
    ).expanduser().resolve()

    if not pipeline_file.is_file():
        raise RuntimeError(
            f"Model pipeline not found at {pipeline_file}. "
            "Run scripts/train_h100.sh or extract the pipeline bundle."
        )
    required_model_paths = [
        model_dir / "preprocess_config.json",
        model_dir / "binary" / "manifest.json",
        model_dir / "binary" / "model",
        model_dir / "type" / "model",
    ]
    missing = [str(path) for path in required_model_paths if not path.exists()]
    if missing:
        raise RuntimeError(
            "Trained model artifacts are missing: " + ", ".join(missing)
        )

    pipeline = _load_pipeline(pipeline_file)
    torch = pipeline.torch
    require_cuda = os.getenv("JAC_INFERENCE_REQUIRE_CUDA", "0") == "1"
    if require_cuda and not torch.cuda.is_available():
        raise RuntimeError(
            "JAC_INFERENCE_REQUIRE_CUDA=1, but PyTorch cannot see CUDA."
        )
    device = torch.device(
        "cuda"
        if torch.cuda.is_available()
        else "mps"
        if torch.backends.mps.is_available()
        else "cpu"
    )
    preprocess_data = json.loads(
        (model_dir / "preprocess_config.json").read_text(encoding="utf-8")
    )
    binary_manifest = json.loads(
        (model_dir / "binary" / "manifest.json").read_text(
            encoding="utf-8"
        )
    )
    config = pipeline.PreprocessConfig(**preprocess_data)
    binary_tokenizer, binary_model = pipeline.load_model_and_tokenizer(
        model_dir / "binary" / "model",
        device,
    )
    type_tokenizer, type_model = pipeline.load_model_and_tokenizer(
        model_dir / "type" / "model",
        device,
    )
    _RUNTIME_CACHE = {
        "pipeline": pipeline,
        "config": config,
        "device": device,
        "binary_tokenizer": binary_tokenizer,
        "binary_model": binary_model,
        "type_tokenizer": type_tokenizer,
        "type_model": type_model,
        "max_length": int(
            binary_manifest.get("training", {}).get("max_length", 256)
        ),
    }
    return _RUNTIME_CACHE


def _clone_repository(repository: str, destination: Path) -> None:
    environment = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    timeout = _positive_int("JAC_GIT_TIMEOUT_SECONDS", 120)
    completed = subprocess.run(
        [
            "git",
            "clone",
            "--depth",
            "1",
            "--filter=blob:none",
            "--single-branch",
            "--no-checkout",
            repository,
            str(destination),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=environment,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip().splitlines()
        message = detail[-1] if detail else "git clone failed"
        raise RuntimeError(f"Could not clone the public repository: {message}")

    tree = subprocess.run(
        ["git", "-C", str(destination), "ls-tree", "-r", "-z", "HEAD"],
        check=False,
        capture_output=True,
        timeout=timeout,
        env=environment,
    )
    if tree.returncode != 0:
        raise RuntimeError("Could not enumerate repository files.")

    jac_paths: list[str] = []
    for entry in tree.stdout.split(b"\0"):
        if not entry or b"\t" not in entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        mode = metadata.split(b" ", 1)[0]
        path = raw_path.decode("utf-8", errors="surrogateescape")
        if mode in {b"100644", b"100755"} and path.endswith(".jac"):
            jac_paths.append(path)
        if len(jac_paths) >= _positive_int("JAC_SCAN_MAX_FILES", 200):
            break

    if jac_paths:
        checkout = subprocess.run(
            [
                "git",
                "-C",
                str(destination),
                "checkout",
                "HEAD",
                "--",
                *jac_paths,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=environment,
        )
        if checkout.returncode != 0:
            raise RuntimeError("Could not check out repository Jac files.")


def _scan_checkout(checkout: Path, repository: str) -> dict[str, object]:
    runtime = _runtime()
    pipeline = runtime["pipeline"]
    config = runtime["config"]
    device = runtime["device"]
    max_files = _positive_int("JAC_SCAN_MAX_FILES", 200)
    max_file_bytes = _positive_int("JAC_SCAN_MAX_FILE_BYTES", 262_144)
    max_windows = _positive_int("JAC_SCAN_MAX_WINDOWS", 10_000)
    batch_size = _positive_int("JAC_SCAN_BATCH_SIZE", 64)
    max_findings = _positive_int("JAC_SCAN_MAX_FINDINGS", 50)
    threshold = _threshold()

    files = sorted(checkout.rglob("*.jac"))[:max_files]
    candidate_rows: list[dict[str, object]] = []
    files_scanned = 0
    for path in files:
        if (
            path.is_symlink()
            or not path.is_file()
            or path.stat().st_size > max_file_bytes
        ):
            continue
        code = path.read_text(encoding="utf-8", errors="replace")
        normalized_source = (
            pipeline.canonicalize_imports(code, strip_imports=False)
            if config.canonicalize_import_aliases
            else code
        )
        window_config = replace(
            config,
            canonicalize_import_aliases=False,
        )
        relative_path = str(path.relative_to(checkout))
        for candidate in pipeline.sliding_windows(
            normalized_source,
            config.window_radius,
            config.scan_stride,
        ):
            candidate_rows.append(
                {
                    "path": relative_path,
                    "start": candidate["start"],
                    "end": candidate["end"],
                    "code": candidate["text"],
                    "input_text": pipeline.normalize_code(
                        candidate["text"],
                        window_config,
                    ),
                }
            )
            if len(candidate_rows) >= max_windows:
                break
        files_scanned += 1
        if len(candidate_rows) >= max_windows:
            break

    if not candidate_rows:
        return {
            "repository": repository.removesuffix(".git"),
            "device": str(device),
            "files_scanned": files_scanned,
            "windows_scanned": 0,
            "findings": [],
        }

    texts = [str(row["input_text"]) for row in candidate_rows]
    binary_probabilities = pipeline.batched_probabilities(
        texts,
        runtime["binary_tokenizer"],
        runtime["binary_model"],
        device,
        runtime["max_length"],
        batch_size,
    )
    vulnerable_id = runtime["binary_model"].config.label2id["VULNERABLE"]
    vulnerable_indices = [
        index
        for index, probability in enumerate(
            binary_probabilities[:, vulnerable_id]
        )
        if probability >= threshold
    ]

    findings_by_path: dict[str, list[dict[str, object]]] = {}
    if vulnerable_indices:
        type_probabilities = pipeline.batched_probabilities(
            [texts[index] for index in vulnerable_indices],
            runtime["type_tokenizer"],
            runtime["type_model"],
            device,
            runtime["max_length"],
            batch_size,
        )
        for local_index, candidate_index in enumerate(vulnerable_indices):
            type_id = int(type_probabilities[local_index].argmax())
            predicted_type = str(
                runtime["type_model"].config.id2label[type_id]
            )
            row = candidate_rows[candidate_index]
            path = str(row["path"])
            binary_confidence = float(
                binary_probabilities[candidate_index, vulnerable_id]
            )
            type_confidence = float(
                type_probabilities[local_index, type_id]
            )
            findings_by_path.setdefault(path, []).append(
                {
                    "line_start": int(row["start"]),
                    "line_end": int(row["end"]),
                    "binary_confidence": binary_confidence,
                    "predicted_type": predicted_type,
                    "vulnerability_confidence": (
                        binary_confidence * type_confidence
                    ),
                    "code": str(row["code"]),
                }
            )

    rendered_findings: list[dict[str, object]] = []
    for path, path_findings in findings_by_path.items():
        for finding in pipeline.non_maximum_suppression(
            path_findings,
            max_findings,
        ):
            predicted_type = str(finding["predicted_type"])
            rendered_findings.append(
                {
                    "title": TYPE_TITLES.get(
                        predicted_type,
                        predicted_type.replace("_", " ").title(),
                    ),
                    "severity": (
                        "High"
                        if predicted_type in HIGH_SEVERITY
                        else "Medium"
                    ),
                    "path": path,
                    "line_start": int(finding["line_start"]),
                    "line_end": int(finding["line_end"]),
                    "confidence": float(
                        finding["vulnerability_confidence"]
                    ),
                }
            )

    rendered_findings.sort(
        key=lambda item: float(item["confidence"]),
        reverse=True,
    )
    return {
        "repository": repository.removesuffix(".git"),
        "device": str(device),
        "files_scanned": files_scanned,
        "windows_scanned": len(candidate_rows),
        "findings": rendered_findings[:max_findings],
    }


def scan_repository(repository: str) -> dict[str, object]:
    """Clone and scan a public GitHub repository with the trained model."""
    started = time.monotonic()
    canonical_repository = _canonical_github_url(repository)
    with _RUNTIME_LOCK:
        _runtime()
    with tempfile.TemporaryDirectory(prefix="jac-security-scan-") as temp_dir:
        checkout = Path(temp_dir) / "repository"
        _clone_repository(canonical_repository, checkout)
        with _RUNTIME_LOCK:
            result = _scan_checkout(checkout, canonical_repository)
    result["elapsed_seconds"] = round(time.monotonic() - started, 2)
    return result
