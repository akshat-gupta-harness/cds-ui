# cds-ui

Local debug page. Paste a PURL and show what differs across the sources you check.

Mongo v1 (`componentEnrichment`), Mongo v2 (`componentEnrichmentV2`), Qwiet, and CDS are each optional. v1 and v2 start checked. Qwiet is the writer for v1; CDS is the writer for v2. Checking both Mongo sides diffs those documents. Checking Qwiet and CDS diffs the two `package_info` payloads the same way, with Mongo left off. A live checkbox also compares CVE ids with the matching stored document when that Mongo side is checked.

Credentials and service URLs stay in `.env` on the server. The browser only talks to localhost.

## Run

The Mongo read uses `python3` and `pymongo`. Start the Mongo tunnel, then the page:

```sh
npm start
```

Open the local address printed at startup.

Set `MONGO_URI` in `.env` to that tunnel when a Mongo source is checked. Live request flags are sent only when Qwiet or CDS is checked.

```sh
npm test
```

## Mongo v1 vs Qwiet (CLI)

Batch-check whether stored `componentEnrichment` matches live Qwiet (`package_info`). PURLs come from the enrichment report fixtures (same examples as `component-data-service` docs `enrichment-v1-v2-cves.md` / `enrichment-v1-v2-licenses.md`).

Requires `MONGO_URI`, `QWIET_URL`, and `QWIET_TOKEN` in `.env`. Start the Mongo tunnel first.

```sh
npm run compare:qwiet                    # all fixture purls (CVE + license suites)
npm run compare:qwiet -- --suite cves
npm run compare:qwiet -- --suite licenses
npm run compare:qwiet -- --purl 'pkg:golang/stdlib@1.26.1'
npm run compare:qwiet -- --json
```

Exit code `0` = no diffs, `1` = at least one diff, `2` = missing config or fetch error.

Override fixture path: `--fixture /path/to/enrichment-report-purls.json` or `ENRICHMENT_PURLS_FIXTURE`.
