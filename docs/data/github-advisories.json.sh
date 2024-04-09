#!/bin/bash
set -euo pipefail

for repo in $(./docs/data/wolfi-packages.json.sh | jq -r '[.[].repo] | unique[]')
do
  >&2 echo $repo
  mkdir -p $(dirname "docs/data/github-repository-security-advisories/${repo}")
  if ! gh api --paginate "/repos/${repo}/security-advisories?per_page=100" > "docs/data/github-repository-security-advisories/${repo}.json"
  then
    # if the API errored, delete the output
    rm "docs/data/github-repository-security-advisories/${repo}.json"
  fi
done

jq -s '[.[][] | {ghsa_id: .ghsa_id, cve_id: ( if .cve_id != "" then .cve_id else null end ), repo: .url | capture("https://api.github.com/repos/(?<repo>[^/]+/[^/]+)").repo } ]' docs/data/github-repository-security-advisories/*/*.json
