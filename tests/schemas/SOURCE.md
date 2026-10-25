# Vendored CycloneDX schemas (test fixtures, unmodified)

Source: https://github.com/CycloneDX/specification (branch `master`, directory `schema/`), downloaded 2026-10-25.
License: Apache-2.0 (see the `$comment` in each file).

| File | URL | sha256 |
|---|---|---|
| bom-1.6.schema.json | https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.6.schema.json | 18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d |
| spdx.schema.json | https://raw.githubusercontent.com/CycloneDX/specification/master/schema/spdx.schema.json | 4b345e2329f209f34e960ae2a8e7cb46a166907e6a45e94978565925dc47b359 |
| jsf-0.82.schema.json | https://raw.githubusercontent.com/CycloneDX/specification/master/schema/jsf-0.82.schema.json | 8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae |

`bom-1.6.schema.json` references the other two by relative `$ref`; the test resolves them from this directory.
The test verifies the sha256 values above before validating.
