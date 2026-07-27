"""Focused regression tests for repository retrieval."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import model_service


class CloneRepositoryTests(unittest.TestCase):
    def test_repository_score_weights_severity_and_confidence(self) -> None:
        findings: list[dict[str, object]] = [
            {
                "path": "main.jac",
                "title": "SQL injection",
                "severity": "High",
                "confidence": 0.8,
            },
            {
                "path": "main.jac",
                "title": "Cross-site scripting",
                "severity": "Medium",
                "confidence": 0.4,
            },
        ]

        self.assertEqual(model_service._repository_score(findings), 59)
        self.assertEqual(model_service._repository_score([]), 100)

    def test_repository_score_does_not_double_count_overlapping_windows(
        self,
    ) -> None:
        findings = [
            {
                "path": "main.jac",
                "title": "SQL injection",
                "severity": "High",
                "confidence": confidence,
            }
            for confidence in (0.65, 0.8, 0.95, 0.7)
        ]

        self.assertEqual(model_service._repository_score(findings), 57)

    def test_repository_score_discounts_additional_distinct_signals(
        self,
    ) -> None:
        findings = [
            {
                "path": f"src/file_{index}.jac",
                "title": "SQL injection",
                "severity": "High",
                "confidence": 1.0,
            }
            for index in range(10)
        ]

        self.assertEqual(model_service._repository_score(findings), 10)

    def test_finding_source_url_targets_exact_encoded_lines(self) -> None:
        self.assertEqual(
            model_service._finding_source_url(
                "https://github.com/example/project.git",
                "src/security checks/auth#flow.jac",
                12,
                18,
            ),
            (
                "https://github.com/example/project/blob/HEAD/"
                "src/security%20checks/auth%23flow.jac#L12-L18"
            ),
        )

    def test_interactive_default_bounds_model_windows(self) -> None:
        with patch.dict(
            model_service.os.environ,
            {},
            clear=True,
        ):
            self.assertEqual(
                model_service._positive_int(
                    "JAC_SCAN_MAX_WINDOWS",
                    model_service.DEFAULT_MAX_WINDOWS,
                ),
                1_000,
            )

    def test_prefetches_only_blobs_within_scan_file_limit(self) -> None:
        tree_output = (
            b"100644 blob abcdef\tmain.jac\0"
            b"100644 blob abcdef\tsrc/frontend.jac\0"
            b"100644 blob abcdef\tdocs/unsafe-example.jac\0"
            b"100644 blob abcdef\ttests/test_scanner.jac\0"
            b"100644 blob abcdef\texamples/demo.jac\0"
            b"100644 blob fedcba\tREADME.md\0"
        )
        completed = [
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 0, tree_output, b""),
            subprocess.CompletedProcess([], 0, "", ""),
        ]

        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch.dict(
                model_service.os.environ,
                {"JAC_SCAN_MAX_FILE_BYTES": "123456"},
            ),
            patch.object(
                model_service.shutil,
                "disk_usage",
                return_value=SimpleNamespace(free=1_000_000_000),
            ),
            patch.object(
                model_service.subprocess,
                "run",
                side_effect=completed,
            ) as run,
        ):
            destination = Path(temp_dir) / "repository"
            model_service._clone_repository(
                "https://github.com/example/project.git",
                destination,
            )

        clone_command = run.call_args_list[0].args[0]
        checkout_command = run.call_args_list[2].args[0]
        self.assertIn("--filter=blob:limit=123456", clone_command)
        path_start = checkout_command.index("--") + 1
        self.assertEqual(
            checkout_command[path_start:],
            ["main.jac", "src/frontend.jac"],
        )

    def test_scan_scope_excludes_non_production_jac_paths(self) -> None:
        included = [
            "main.jac",
            "src/api.jac",
            "client/components/results.jac",
        ]
        excluded = [
            "docs/sql-injection.jac",
            "documentation/auth.jac",
            "tests/scanner.jac",
            "src/test_api.jac",
            "src/api_test.jac",
            "src/api.spec.jac",
            "examples/vulnerable-app.jac",
            "fixtures/repository.jac",
            "benchmarks/parser.jac",
            "vendor/library.jac",
        ]

        for path in included:
            with self.subTest(path=path):
                self.assertTrue(model_service._is_scannable_jac_path(path))
        for path in excluded:
            with self.subTest(path=path):
                self.assertFalse(model_service._is_scannable_jac_path(path))

    def test_rejects_scan_when_temporary_disk_is_too_full(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch.dict(
                model_service.os.environ,
                {"JAC_SCAN_MIN_FREE_BYTES": "1000"},
            ),
            patch.object(
                model_service.shutil,
                "disk_usage",
                return_value=SimpleNamespace(free=500),
            ),
            patch.object(model_service.subprocess, "run") as run,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "Not enough free disk space",
            ):
                model_service._clone_repository(
                    "https://github.com/example/project.git",
                    Path(temp_dir) / "repository",
                )

        run.assert_not_called()

    def test_reports_checkout_timeout_without_full_command(self) -> None:
        tree_output = b"100644 blob abcdef\tmain.jac\0"
        completed = [
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 0, tree_output, b""),
            subprocess.TimeoutExpired(["git", "checkout"], 7),
        ]

        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch.dict(
                model_service.os.environ,
                {"JAC_GIT_TIMEOUT_SECONDS": "7"},
            ),
            patch.object(
                model_service.shutil,
                "disk_usage",
                return_value=SimpleNamespace(free=1_000_000_000),
            ),
            patch.object(
                model_service.subprocess,
                "run",
                side_effect=completed,
            ),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "Fetching repository Jac files timed out after 7 seconds",
            ):
                model_service._clone_repository(
                    "https://github.com/example/project.git",
                    Path(temp_dir) / "repository",
                )


if __name__ == "__main__":
    unittest.main()
