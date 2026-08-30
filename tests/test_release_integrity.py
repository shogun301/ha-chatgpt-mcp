from __future__ import annotations

import unittest
import os
from unittest.mock import patch

from scripts import release_integrity
from scripts import public_release_audit


class ReleaseIntegrityTests(unittest.TestCase):
    def test_docker_sources_are_tracked_and_present(self) -> None:
        sources = release_integrity.verify_docker_inputs(
            archive=os.environ.get("RELEASE_ARCHIVE") == "1"
        )
        self.assertIn("uv.lock", sources)
        self.assertIn("collector", sources)
        self.assertIn("home_assistant", sources)
        self.assertIn("scripts", sources)

    def test_project_and_release_versions_match(self) -> None:
        self.assertEqual(release_integrity.verify_versions(), "2.7.6")

    def test_manifest_references_exist(self) -> None:
        references = release_integrity.verify_manifests()
        self.assertIn("pyproject.toml", references)
        self.assertIn("uv.lock", references)

    def test_release_automation_contains_all_clean_context_gates(self) -> None:
        release_integrity.verify_release_automation()

    def test_wyze_overlay_assets_and_base_guard_are_complete(self) -> None:
        files = release_integrity.verify_wyze_overlay(
            archive=os.environ.get("RELEASE_ARCHIVE") == "1"
        )
        self.assertEqual(files, sorted(release_integrity.WYZE_OVERLAY_FILES))

    def test_wyze_overlay_has_public_safe_license_attribution(self) -> None:
        self.assertEqual(public_release_audit.audit_overlay_distribution(), [])
        readme = release_integrity.WYZE_OVERLAY_ROOT / "README.md"
        self.assertFalse(public_release_audit.USER_PROFILE_RE.search(readme.read_text()))

    def test_registry_contract_has_input_output_and_annotation_hashes(self) -> None:
        self.assertEqual(
            release_integrity.verify_registry_contract(),
            "tests/fixtures/server-contract-2.7.6.json",
        )

    def test_untracked_copied_directory_fails_closed(self) -> None:
        if os.environ.get("RELEASE_ARCHIVE") == "1":
            self.skipTest("git archive contains tracked files only")
        tracked = release_integrity._tracked_files()
        with patch.object(
            release_integrity, "_tracked_files",
            return_value={item for item in tracked if not item.startswith("app/")},
        ):
            with self.assertRaisesRegex(AssertionError, "not tracked"):
                release_integrity.verify_docker_inputs(archive=False)


if __name__ == "__main__":
    unittest.main()
