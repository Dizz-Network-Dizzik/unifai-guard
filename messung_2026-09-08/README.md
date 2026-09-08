# Capture of the live catalogue, 8 Sep 2026

A union over 50 queries against the UnifAI public search API on 8 Sep 2026:
**183 distinct actions across 45 toolkits, 811 free-text `description` fields.**
A floor, not a census -- the API caps a single query at 100 results.

It is here so that every claim the README makes about the real catalogue can
be checked rather than believed. `tests/test_real_catalogue.py` uses it as a
false-positive corpus and skips itself if the file is absent.

| file | what it is |
|---|---|
| `actions_full.json` | key -> description + payload, as returned |
| `actions_census.json` | key -> description only |
| `scan_ergebnis.json` | the scan result, anonymised (no toolkit names) |

**This goes stale immediately.** Re-run against the live API for current data;
the numbers in the README all carry the capture date for that reason.
