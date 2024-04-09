#!/bin/bash
set -euo pipefail
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
cd $tmp

curl -L -s --fail-with-body https://github.com/wolfi-dev/advisories/archive/refs/heads/main.tar.gz | tar xz
cd advisories-main

yq -sr '[ .[] | .package.name as $pkg | {package: $pkg, advisories: [.advisories[] | [.id, (.aliases//[])[] ] ] } ]' *.advisories.yaml
