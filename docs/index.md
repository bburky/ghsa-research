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

TODO: these issues are _not_ specific to Chainguard Wolfi at all, and are mostly a result of some hard to use GitHub APIs not exposing all GHSA data in bulk

TODO: do this same analysis against packages from other linux distros

The GHSA repository advisories listed below have been found on the upstream GitHub repository, but are not listed Chainguard's Wolfi `*.advisories.yaml` file.

In most cases, the Wolfi package has actually been updated to a patched version unaffected by the CVE. This is because Wolfi is rolling release distro and auto updates most software to latest version, regardless of CVEs. The missing advisory is still an issue because users are not informed that their old version was affected by a CVE and they need to update to the latest version.

Version numbers aren't checked in this analysis. This is intentional as mentioned above, but if Wolfi never distributed a affected version affected by a CVE, they usually don't list the advisory. So some advisories may be incorrectly listed here that never affected a Wolfi package.

Also, sometimes when packages have breaking changes, Wolfi creates a new package "stream" with the bumped version, duplicating the package. This may result in duplicate data here, and new GHSAs may be incorrectly shown against the old package. This is really just another case of not checking versions.

You can compare manually this data at https://images.chainguard.dev/security/

Which mentions:

> Advisories are based on vulnerability information provided by Grype from Anchore.

Many of the missing CVEs are also missing from Grype (as rich GHSA GitHub data at least, some of them exist as CVEs in the NVD data but are unlinked to any packages or GitHub repos).

Grype (and many, many, other tools) use GitHub _global security advisory_ data from https://github.com/advisories (often downloaded in bulk from its [git repo](https://github.com/github/advisory-database) or using its [GraphQL API](https://docs.github.com/en/rest/security-advisories/global-advisories?apiVersion=2022-11-28)). This data does NOT include _repository_ advisories, which are only available via [a specific REST API](https://docs.github.com/en/rest/security-advisories/repository-advisories?apiVersion=2022-11-28), which must be fetched individually per-repo. If advisories do not list an packages do not have a [supported ecosystem](https://github.com/github/advisory-database?tab=readme-ov-file#supported-ecosystems) (golang, npm, etc), they do not become a "GitHub reviewed" advisory with rich data linking to the affected package. NVD CVE data _is_ included, but this includes none of the rich data from the repository advisory, there isn't even any machine readable data linking back to the source GitHub repo, and the data is incomplete with many repository advisory CVEs missing entirely.

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
