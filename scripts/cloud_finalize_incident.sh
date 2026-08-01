#!/usr/bin/env bash
# cloud_finalize_incident.sh PRIVATE_PLAIN_DIR BUNDLE VALIDATE_OUTCOME SUMMARY_OUTCOME
#
# Private finalizer for the "Encrypt evidence and verify plaintext cleanup"
# step of .github/workflows/hunt.yml, which carries if: ${{ always() }} so
# that NO post-fuzzer gate failure (corpus validation, seven-field summary)
# can skip evidence securing (R3-4).
#
# Contract:
#   - if private_plain exists: package it with GPG and verify cleanup;
#     success leaves evidence.gpg as the only input remnant;
#   - if GPG or cleanup fails on the hosted runner: there is no safe channel
#     to keep plaintext, so the plaintext is destroyed (shred) before the
#     step ends; zero upload, zero publish, non-zero exit;
#   - if any prior gate outcome is not "success" the evidence is still
#     secured first, then this script exits non-zero so upload and publish
#     are skipped (no corpus is ever published after a failed gate);
#   - exit 0 only when evidence is secured AND every prior gate succeeded.
set -euo pipefail
umask 077

if [[ "$#" -ne 4 ]]; then
    printf 'usage: %s PRIVATE_PLAIN_DIR BUNDLE VALIDATE_OUTCOME SUMMARY_OUTCOME\n' "$0" >&2
    exit 64
fi

PRIVATE_DIR="$1"
BUNDLE="$2"
VALIDATE_OUTCOME="$3"
SUMMARY_OUTCOME="$4"

PACKAGER="scripts/package_incident.py"
PUBLIC_KEY="keys/artifact-recipient.asc"
FINGERPRINT="keys/artifact-recipient.fingerprint"

prior_ok=0
if [[ "${VALIDATE_OUTCOME}" == "success" && "${SUMMARY_OUTCOME}" == "success" ]]; then
    prior_ok=1
fi

secured=0
if [[ -d "${PRIVATE_DIR}" && ! -L "${PRIVATE_DIR}" ]]; then
    if python3 "${PACKAGER}" "${PRIVATE_DIR}" "${PUBLIC_KEY}" "${FINGERPRINT}" "${BUNDLE}" &&
       [[ -s "${BUNDLE}" && ! -L "${BUNDLE}" ]] && [[ ! -e "${PRIVATE_DIR}" ]]; then
        secured=1
    else
        # GPG/cleanup failure on a hosted runner: no quarantine channel
        # exists, so the plaintext is destroyed before the step ends. The
        # partial bundle is not evidence (it never verified) and is removed
        # with the plaintext; upload and publish never run after this.
        if [[ -d "${PRIVATE_DIR}" ]]; then
            find "${PRIVATE_DIR}" -type f -exec shred -u -- {} + 2>/dev/null || true
            rm -rf -- "${PRIVATE_DIR}"
        fi
        rm -f -- "${BUNDLE}"
        exit 1
    fi
fi

# Nothing to secure (runner died before private_plain existed) or a prior
# gate failed: fail closed. Upload/publish are gated on this step's success.
[[ "${secured}" -eq 1 ]] || exit 1
[[ "${prior_ok}" -eq 1 ]] || exit 1
exit 0
