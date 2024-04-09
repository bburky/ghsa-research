#!/bin/bash
set -euo pipefail
curl -s --fail "https://security-tracker.debian.org/tracker/data/json" | jq -r '["cve","package"], (to_entries[] | .key as $pkg | .value | keys[] | [., $pkg]) | @csv'

# CVE HTML URL format: https://security-tracker.debian.org/tracker/$cve