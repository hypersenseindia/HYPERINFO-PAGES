# HYPERINFO &mdash; Pages

The **page-by-page GUI edition** of HYPERINFO: instead of one wall of text, the results are split into screens you page through &mdash; network, DNS, certificates, reputation, contacts &mdash; with a saved report for each run.

Bash, Termux, passive lookups only.

## Why pages

A full OSINT dump is hard to read on a phone. This build breaks the same data into focused screens, so you can stop at the section you need and skip the rest.

## Run

```bash
pkg install -y git python whois
git clone https://github.com/hypersenseindia/HYPERINFO-PAGES
cd HYPERINFO-PAGES
chmod +x HYPERINFO_PAGES.sh
./HYPERINFO_PAGES.sh
```

Run passcode: `321`

Reports are written to `.hyperinfo_pages/` in the current directory.

## Optional keys

```bash
export SHODAN_API_KEY="..."    # open ports and banners
export HUNTER_API_KEY="..."    # public contact records
export IPINFO_TOKEN="..."      # geolocation detail
```

Every stage degrades gracefully: no key, no stage.

## Editions

- [HYPERINFO-hypersenseindia](https://github.com/hypersenseindia/HYPERINFO-hypersenseindia) &mdash; original
- [HYPERINFO-FINAL](https://github.com/hypersenseindia/HYPERINFO-FINAL) &mdash; final CLI build
- **This repository** &mdash; page-by-page GUI

## Legal

Passive collection of public records only. Do not use it to harass or identify private individuals.
---

<p align="center">
  <sub>Built by <b>AG HYDRAXFF</b> &mdash; HYPERSENSEGLOBAL &middot;
  <a href="https://www.instagram.com/hydraxff_yt/">@hydraxff_yt</a></sub>
</p>