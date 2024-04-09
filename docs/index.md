---
title: "Untracked repository GHSA advisories: Chainguard Wolfi"
theme: wide
toc: false
sql:
  wolfi_advisories: "./data/wolfi-advisories.json"
  wolfi_packages: "./data/wolfi-packages.json"
  ghsa_advisories: "./data/github-advisories.json"
---

# Untracked repository GHSA advisories: Chainguard Wolfi

_Note: The broader issue of missing GHSA CVE data is **not** specific to Chainguard Wolfi or any other linux distribution. This is mostly a result of some hard to use GitHub APIs not exposing all GHSA data in bulk. However some advisories may be listed here for other reasons such as incorrect detection of dependencies._

TODO: do this same analysis against packages from other linux distros

The GHSA repository advisories listed below have been found on the upstream GitHub repository, but are not listed Chainguard's Wolfi `*.advisories.yaml` file.

In most cases, the Wolfi package has actually been updated to a patched version unaffected by the CVE. This is because Wolfi is rolling release distro and auto updates most software to latest version, regardless of CVEs. The missing advisory is still an issue because users are not informed that their old version was affected by a CVE and they need to update to the latest version.

Version numbers aren't checked in this analysis. This is intentional as mentioned above, but if Wolfi never distributed a affected version affected by a CVE, they usually don't list the advisory. So some advisories may be incorrectly listed here that never affected a Wolfi package.

Also, sometimes when packages have breaking changes, Wolfi creates a new package "stream" with the bumped version, duplicating the package. This may result in duplicate data here, and new GHSAs may be incorrectly shown against the old package. This is really just another case of not checking versions.

You can compare manually this data at https://images.chainguard.dev/security/

Which mentions:

> Advisories are based on vulnerability information provided by Grype from Anchore.

Many of the missing CVEs are also missing from Grype (as rich GHSA GitHub data at least, some of them exist as CVEs in the NVD data but are unlinked to any packages or GitHub repos).

Grype (and many, many, other tools) use GitHub _global security advisory_ data from https://github.com/advisories (often downloaded in bulk from its [git repo](https://github.com/github/advisory-database) or using its [GraphQL API](https://docs.github.com/en/rest/security-advisories/global-advisories?apiVersion=2022-11-28)). This data does NOT include _repository_ advisories, which are only available via [a specific REST API](https://docs.github.com/en/rest/security-advisories/repository-advisories?apiVersion=2022-11-28), which must be fetched individually per-repo. If advisories do not list packages in a [supported ecosystem](https://github.com/github/advisory-database?tab=readme-ov-file#supported-ecosystems) (golang, npm, etc), they typically do not become a "GitHub reviewed" global advisory with rich data linking to the affected package. NVD CVE data _is_ included, but this includes none of the rich data from the repository advisory, there isn't even any machine readable data linking back to the source GitHub repo, and the data is incomplete with many repository advisory CVEs missing entirely.
Grype (and many, many, other tools) use GitHub _global security advisory_ data from https://github.com/advisories (often downloaded in bulk from its [git repo](https://github.com/github/advisory-database) or using its [GraphQL API](https://docs.github.com/en/rest/security-advisories/global-advisories?apiVersion=2022-11-28)). This data does NOT include _repository_ advisories, which are only available via [a specific REST API](https://docs.github.com/en/rest/security-advisories/repository-advisories?apiVersion=2022-11-28), which must be fetched individually per-repo. If advisories do not list packages in a [supported ecosystem](https://github.com/github/advisory-database?tab=readme-ov-file#supported-ecosystems) (golang, npm, etc), they typically do not become a "GitHub reviewed" global advisory linking to the affected package. NVD CVE data _is_ included in the global, but this includes none of the rich data from the repository advisory, there isn't even any machine readable data linking back to the source GitHub repo, and the data is incomplete with many repository advisory CVEs missing entirely.

### Findings

A couple selected findings from the data:

#### Missing advisory data

For most of the CVEs, Chainguard has already updated the software to the newest version, they just failed to list an advisory for it. This is great if users perhaps use a `latest` tag and always update frequently. However, many users wont't always update to the newest version unless an advisory against the old package is published.

An example of a missing advisory against a Wolfi package:

- Wolfi did previously package Helm 3.14.1: https://github.com/wolfi-dev/os/commit/0b4859e5c03f0f424276e6cee8ab4db4410fbe24
- CVE-2024-26147, GHSA-r53h-jv2g-vpx6 advisory affects 3.14.1: https://github.com/advisories/GHSA-r53h-jv2g-vpx6
- Advisory is missing from Wolfi advisories: https://github.com/wolfi-dev/advisories/blob/main/helm.advisories.yaml

I don't know why Grype didn't detect this CVE against Helm, it's not a non-ecosystem package: the advisory lists a golang package name. Weirdly this CVE does appear in Wolfi advisories against _other_ packages dependent on Helm.

#### Unpatched package

I did notice a significant unpatched CVE in Minio:

- Minio Wolfi package was RELEASE.2023-10-25T06-33-25Z https://github.com/wolfi-dev/os/blob/1a1133adf240f10dd716f8494b982bd69b4484e2/minio.yaml#L5
- CVE-2024-24747 GHSA-xx8w-mq23-29g4 advisory affecting 20240131185645 and older https://github.com/advisories/GHSA-xx8w-mq23-29g4
- Grype does detect the Minio golang module and version in Wolfi packages, but Minio's strange version numbering probably prevents detecting that the old version is affected.
- Auto-updates [were disabled](https://github.com/wolfi-dev/os/blob/1a1133adf240f10dd716f8494b982bd69b4484e2/minio.yaml#L38-L39) on the Minio Wolfi package
- UPDATE: This has been fixed. [Mino was updated to 20240406](https://github.com/wolfi-dev/os/pull/16564).

### All data

```sql echo id=missing_advisories
-- TODO: make this code cleaner. Probably use another subquery to avoid repeated unnest()
-- TODO: add affected/fixed version numbers from GHSA data
select
    packages.package,
    packages.version,
    packages.repo,
    -- Advisories have multiple identifiers: both GHSA and CVE numbers. For each advisory's set of ids, check if the Wolfi data (all ids from the Wolfi package, flattened list) includes any of the ids.
    unnest(list_filter(packages.github_advisories, github_advisory -> not list_has_any(github_advisory, flatten(wolfi_advisories.advisories))))[1] as ghsa,
    unnest(list_filter(packages.github_advisories, github_advisory -> not list_has_any(github_advisory, flatten(wolfi_advisories.advisories))))[2] as cve,
from (
    select
        wolfi_packages.package as package,
        arbitrary(wolfi_packages.version) as version,
        arbitrary(ghsa_advisories.repo) as repo,
        list(list_distinct([ghsa_advisories.cve_id, ghsa_advisories.ghsa_id])) as github_advisories,
    from ghsa_advisories
    join wolfi_packages on wolfi_packages.repo = ghsa_advisories.repo
    group by wolfi_packages.package
) as packages
join wolfi_advisories on packages.package = wolfi_advisories.package
where list_filter(packages.github_advisories, github_advisory -> not list_has_any(github_advisory, flatten(wolfi_advisories.advisories))) != []
```

```js
display(
  html`<tr>
    <th>Wolfi package and current version</th>
    <th>Detected repo</th>
    <th>Missing GHSA</th>
    <th>Missing CVE</th>
  </tr>`
);
for (const a of missing_advisories) {
  const repo_link = `https://github.com/${a.repo}`;
  const ghsa_link = `https://github.com/${a.repo}/security/advisories/${a.ghsa}`;
  const wolfi_package_link = `https://github.com/wolfi-dev/os/blob/main/${a.package}.yaml`;
  const wolfi_advisory_link = `https://github.com/wolfi-dev/advisories/blob/main/${a.package}.advisories.yaml`;
  display(
    html`<tr>
      <td>
        <a href=${wolfi_package_link}>${a.package}</a>
        <small><i>${a.version}</i></small>
        <span style="margin: auto 1em; font-variant: small-caps"
          ><a href=${wolfi_advisory_link}>advisories</a>
        </span>
      </td>
      <td><a href=${repo_link}>${a.repo}</a></td>
      <td><a href=${ghsa_link}>${a.ghsa}</a></td>
      <td>${a.cve}</td>
    </tr>`
  );
}
```

```js
// Output source code for data loaders
// https://github.com/observablehq/framework/discussions/842#discussioncomment-8502197
import hljs from "npm:highlight.js";
const files = [
  FileAttachment("./data/wolfi-advisories.json.sh"),
  FileAttachment("./data/wolfi-packages.json.sh"),
  FileAttachment("./data/github-advisories.json.sh"),
];
for (const f of files) {
  display(html`<h2>${f.name}</h2>`);
  const code = await f.text();
  const div = display(document.createElement("pre"));
  div.innerHTML = hljs.highlight(code, { language: "bash" }).value;
}
```
