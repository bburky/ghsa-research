#!/bin/bash
set -euo pipefail
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
cd $tmp

curl -L -s --fail-with-body https://github.com/wolfi-dev/os/archive/refs/heads/main.tar.gz | tar xz
cd os-main

# TODO fix:
# https://github.com/wolfi-dev/os/blob/908fa8bd232e10bf7fc911ab89cbe9502fe0fc70/msgpack-c.yaml#L24
# https://github.com/wolfi-dev/os/blob/908fa8bd232e10bf7fc911ab89cbe9502fe0fc70/opensearch-2.yaml#L161

# We could parse out the `repository:` from `uses: git-checkout` pipeline entries, but a simple regex additioanlly catches other types of pipeline steps that don't include `uses: git-checkout`
# This does incorrectly pull some broken repo names sometimes, they are not validated here
yq -cs '.[] | ([.package.name as $pkg | .package.version as $version | .. | select(. | type == "string") | capture("https?://github\\.com/(?<repo>[^/]+/[^/.#?\n \"'\'']+)") | {package: $pkg, version: $version, repo: .repo}]  | unique[] ) ' *.yaml | jq -s '[ .[] ]'
