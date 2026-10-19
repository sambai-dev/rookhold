from __future__ import annotations

import runpy
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECK = runpy.run_path(str(ROOT / "scripts" / "check-pr-description.py"))


def valid_body() -> str:
    return """## Contribution tier
Tier C — executor, authentication, storage, receipts, or isolation.

## Declared scope
Repair one independently useful parser behavior without claiming the sibling command.

## Root invariant
Every accepted candidate is classified once and rejected candidates never fall through.

## Reproduction and RED evidence
RED: the focused test failed on the unchanged source because the valid label was skipped.

## Changes
Repair the classifier predicate and keep the parser contract otherwise unchanged.

## Adversarial coverage
- [x] null-like and annotated values
- [x] leading spacer cells and classifier fallthrough

## Validation
- Head: 0123456789abcdef
- Checks: focused regression, affected suite, lint, and required CI are green.

## Non-goals and remaining work
The separate all-target command remains out of scope and is recorded independently.

## Safety and compatibility
No wire-format change; the accepted input set only gains previously valid cases.

## Completion state
- Implementation: complete for the declared scope
- Validation: complete on the exact head above
- Review: pending maintainer approval
- Integration: pending merge through the protected branch
"""


class PullRequestDescriptionTests(unittest.TestCase):
    def test_complete_contract_passes(self) -> None:
        self.assertEqual(CHECK["validate_body"](valid_body()), [])

    def test_tier_a_needs_only_scope_changes_and_relevant_validation(self) -> None:
        body = """## Contribution tier
Tier A — documentation, examples, and integrations.

## Declared scope
Add one copyable recipe without changing the execution service.

## Changes
Add the recipe and link it from the examples index.

## Validation
Ran the recipe syntax check and the documentation link checker.
"""
        self.assertEqual(CHECK["validate_body"](body), [])

    def test_missing_scope_and_placeholder_sections_fail(self) -> None:
        body = valid_body().replace("## Declared scope", "## Context").replace(
            "RED: the focused test failed on the unchanged source because the valid label was skipped.",
            "<!-- add evidence -->",
        )
        errors = CHECK["validate_body"](body)
        self.assertIn("missing section: Declared scope", errors)
        self.assertIn(
            "section has no concrete evidence: Reproduction and RED evidence", errors
        )

    def test_adversarial_and_completion_fields_cannot_remain_template_defaults(self) -> None:
        body = valid_body().replace("- [x] null-like and annotated values", "- [ ] null-like values")
        body = body.replace("- [x] leading spacer cells and classifier fallthrough", "")
        body = body.replace(
            "- Validation: complete on the exact head above",
            "- Validation: choose complete or pending",
        )
        errors = CHECK["validate_body"](body)
        self.assertTrue(any("Adversarial coverage" in error for error in errors))
        self.assertIn("Completion state must declare validation status", errors)

    def test_final_head_requires_sha_and_concrete_checks(self) -> None:
        body = valid_body().replace("- Head: 0123456789abcdef", "- Head: latest")
        body = body.replace(
            "- Checks: focused regression, affected suite, lint, and required CI are green.",
            "- Checks: ok",
        )
        errors = CHECK["validate_body"](body)
        self.assertIn("Tier C validation must include 'Head: <commit SHA>'", errors)
        self.assertIn("Tier C validation must include concrete 'Checks:'", errors)

    def test_dependabot_security_pr_with_metadata_is_accepted(self) -> None:
        pr = {
            "user": {"login": "dependabot[bot]"},
            "body": (
                "Bumps source-map-js from 1.2.1 to 1.2.2.\n"
                "---\nupdated-dependencies:\n- dependency-name: source-map-js\n...\n"
                "Signed-off-by: dependabot[bot] <support@github.com>\n"
            ),
        }
        self.assertTrue(CHECK["is_dependabot_security_pr"](pr))

    def test_non_dependabot_user_cannot_spoof_dependabot_metadata(self) -> None:
        pr = {
            "user": {"login": "regular-user"},
            "body": "updated-dependencies:\nSigned-off-by: dependabot[bot]",
        }
        self.assertFalse(CHECK["is_dependabot_security_pr"](pr))


if __name__ == "__main__":
    unittest.main()
