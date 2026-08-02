from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
HUNT = (ROOT / ".github" / "workflows" / "hunt.yml").read_text(encoding="utf-8")


def step(name: str) -> str:
    marker = f"      - name: {name}"
    start = HUNT.index(marker)
    end = HUNT.find("\n      - name: ", start + len(marker))
    if end < 0:
        end = len(HUNT)
    return HUNT[start:end]


class CloudWindowWorkflowTests(unittest.TestCase):
    def test_plan_resolves_one_brain_revision_and_exports_it(self) -> None:
        # Catches every shard independently following a moving corpus-pool head.
        self.assertIn("brain_sha: ${{ steps.brain_revision.outputs.sha }}", HUNT)
        checkout = step("Checkout private brain revision for the wave")
        self.assertIn("repository: creador777/fireblocks-mpc-brain", checkout)
        self.assertIn("ref: corpus-pool", checkout)
        self.assertIn("token: ${{ secrets.FIREBLOCKS_BRAIN_READ_TOKEN }}", checkout)
        self.assertIn("persist-credentials: false", checkout)
        resolver = step("Resolve one exact private brain revision")
        self.assertIn('sha="$(git rev-parse HEAD)"', resolver)
        self.assertIn("printf 'sha=%s\\n'", resolver)

    def test_full_workflow_rerun_fails_closed_before_brain_is_repinned(self) -> None:
        # Catches re-running plan at a newer private HEAD under the same run number.
        guard = step("Reject full workflow reruns that could repin the brain")
        self.assertIn("RUN_ATTEMPT: ${{ github.run_attempt }}", guard)
        self.assertIn('[[ "${RUN_ATTEMPT}" =~ ^[0-9]+$ ]]', guard)
        self.assertIn('(( RUN_ATTEMPT == 1 ))', guard)
        self.assertIn(
            "status=fail_closed code=full_rerun_requires_new_wave",
            guard,
        )

    def test_every_hunt_shard_checks_out_the_plan_sha(self) -> None:
        # Catches one shard reading a newer master than its siblings.
        checkout = step("Checkout pinned private brain read-only")
        self.assertIn("ref: ${{ needs.plan.outputs.brain_sha }}", checkout)
        self.assertNotIn("ref: corpus-pool", checkout)
        self.assertEqual(HUNT.count("ref: ${{ needs.plan.outputs.brain_sha }}"), 1)

    def test_window_rotation_uses_run_number_not_attempt_or_wall_clock(self) -> None:
        # Catches a retry choosing different inputs after infrastructure failure.
        block = step("Materialize deterministic 24-unit corpus window privately")
        self.assertIn("python3 scripts/materialize_window.py", block)
        self.assertIn('"${{ needs.plan.outputs.count }}"', block)
        self.assertIn('"${GITHUB_RUN_NUMBER}"', block)
        self.assertNotIn("GITHUB_RUN_ATTEMPT", block)
        self.assertNotIn("date ", block)

    def test_materializer_output_never_reaches_the_public_actions_log(self) -> None:
        # Catches removing private redirection or leaving its sidecar in the summary allowlist.
        block = step("Materialize deterministic 24-unit corpus window privately")
        self.assertIn('mkdir -p "${root}/corpus" "${root}/output/private_plain"', block)
        self.assertIn('>"${root}/output/private_plain/materialize.log" 2>&1', block)
        self.assertIn('rm -f -- "${root}/output/private_plain/materialize.log"', block)
        self.assertIn('rmdir -- "${root}/output/private_plain"', block)

    def test_existing_gpg_seven_field_and_private_publish_gates_remain(self) -> None:
        # Catches bypassing encryption/cleanup, expanding public output, or skipping validation.
        finalize = step("Encrypt evidence and verify plaintext cleanup")
        upload = step("Upload encrypted bundle only")
        publish = step("Publish corpus and encrypted incident to a unique private branch")
        emit = step("Emit only the seven-field public summary")
        self.assertIn("if: ${{ always() }}", finalize)
        self.assertIn("cloud_finalize_incident.sh", finalize)
        self.assertIn("test ! -e", finalize)
        self.assertIn(".gpg", upload)
        self.assertNotIn("private_plain", upload)
        self.assertIn("publish_ingest.sh", publish)
        self.assertIn("emit_summary.py", emit)

    def test_aggregate_has_capacity_for_twenty_five_private_branches(self) -> None:
        aggregate = HUNT[HUNT.index("  aggregate:") :]
        self.assertIn("timeout-minutes: 60", aggregate)


if __name__ == "__main__":
    unittest.main(verbosity=2)
