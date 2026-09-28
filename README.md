# cds-ui

Local debug page. Paste a PURL, fetch live `package_info` from CDS QA and Qwiet prod, and compare the responses.

Credentials and service URLs stay in `.env` on the server. The browser only talks to localhost.

## Run

```sh
npm start
```

Open the local address printed at startup.

Both calls get the same query flags (latest version, EOL, dependency graph, package score). Uncheck a flag if one upstream rejects it.

```sh
npm test
```
