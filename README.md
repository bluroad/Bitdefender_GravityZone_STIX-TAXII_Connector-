# GravityZone IOC STIX7TAXII Connector 


Python connector that imports Indicators of Compromise (IOCs) into the **Bitdefender GravityZone Cloud** console through the Public API (JSON-RPC 2.0, `addToBlocklist` method).

Supported sources are **MISP** (including the ACN MISP), **TAXII 2.1** (STIX indicators) and **local files**.

> **Project status:** parsing, normalization and payload construction have been verified locally (dry run and mocked HTTP calls). 

## What is sent to GravityZone

| IOC type | How it is handled |
|---|---|
| MD5 / SHA-256 hashes | Blocklist rule `type = hash` |
| IPs (IPv4 / IPv6) | Blocklist rule `type = connection` (`protocol: any`, `direction: both`, `remoteAddress.ipMask = <ip>`) |
| Domains and URLs | **Not supported** by `addToBlocklist`: saved to `iocs_not_pushed.csv` |

Private, loopback, link-local, multicast and reserved IPs are discarded before submission.

Domains and URLs must be enforced with other GravityZone modules (for example Network Protection / Content Control), not with this connector.

## Requirements

- Python 3.9 or later
- A GravityZone API key with the **Incidents** area enabled
- Network access to the GravityZone console and to the chosen source (MISP or TAXII server)

```bash
pip install -r requirements.txt
```

`requirements.txt`:

```
requests
taxii2-client
```

`taxii2-client` is only needed for the TAXII source.

### Endpoint requirements

The submitted rules only take effect if, on the endpoints:

1. the **Blocklist** module is enabled in the policy;
2. the matching rule types are enabled in the policy (**Application Hash** for hashes, **Connection rules** for IPs);
3. for `connection` rules, the **Firewall** module is installed: without it, network connection blocking is not available.

## Configuration

Configuration is done through environment variables. Never hard-code credentials or commit them to the repository.

| Variable | Required for | Description |
|---|---|---|
| `GZ_API_URL` | live submission | GravityZone API Access URL (My Account > Control Center API), in the form `https://<instance>/api` |
| `GZ_API_KEY` | live submission | API key generated in My Account > API keys |
| `GZ_COMPANY_ID` | **not required** | Target company ID. If omitted, rules are created in the API key's own company |
| `MISP_URL` | `--source misp` | MISP instance base URL |
| `MISP_KEY` | `--source misp` | MISP API key |
| `TAXII_URL` | `--source taxii` | Full URL of the TAXII 2.1 collection |
| `TAXII_USER` / `TAXII_PASSWORD` | `--source taxii` | TAXII server credentials |
| `TLS_CA_BUNDLE` | optional | Path to a custom CA bundle used for MISP TLS verification |

### Minimum configuration

To submit to GravityZone, **the URL and the API key are enough**: no other identifier is required.

```bash
export GZ_API_URL="https://<your-access-url>/api"
export GZ_API_KEY="your-api-key"
```

`GZ_COMPANY_ID` is only needed if you manage several companies from a single console (for example with a partner/MSP account) and want to target a company other than the one the API key belongs to. With a single company, leave it empty. On your first test, check in Control Center, under Blocklist, that the rules appear in the expected company.

## Usage

```bash
# Dry run, nothing is sent (recommended first step)
python gz_ioc_connector.py --source misp --dry-run

# MISP: indicators from the last few days
python gz_ioc_connector.py --source misp --misp-last 1d

# TAXII 2.1: indicators added after a given date
python gz_ioc_connector.py --source taxii --since 2026-10-01T00:00:00Z

# Local file (one IOC per line, or "type,value")
python gz_ioc_connector.py --source file --file iocs.csv

# Hashes only, no IP rules
python gz_ioc_connector.py --source misp --no-ip
```

### Main options

| Option | Description |
|---|---|
| `--source {misp,taxii,file}` | IOC source (required) |
| `--file PATH` | Input file for `--source file` |
| `--since ISO8601` | `added_after` filter for TAXII |
| `--misp-last 7d` | Time window for MISP (default `7d`) |
| `--batch-size N` | Rules per API call (default `50`) |
| `--no-ip` | Do not submit IPs as `connection` rules |
| `--dry-run` | Parse and report without calling GravityZone |
| `--state PATH` | State file (default `gz_ioc_state.json`) |
| `--unsupported-out PATH` | CSV file for domains/URLs (default `iocs_not_pushed.csv`) |
| `--note TEXT` | Note attached to the created rules |
| `-v` | Verbose logging |

### Input file format

One IOC per line. The type can be given explicitly or auto-detected. Lines starting with `#` are comments.

```
# hash, IP, domain and URL
44d88612fea8a8f36de82e1278abb02f
sha256,275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
203.0.113.50
evil.example.com
http://bad.example.com/payload.php
```

## How it works

1. Reads IOCs from the chosen source.
   - **MISP:** published attributes with `to_ids` enabled, via `/attributes/restSearch`.
   - **TAXII:** non-revoked `indicator` objects, using STIX patterns for hashes, IPs, domains and URLs.
2. Normalizes and validates each indicator, and removes duplicates.
3. Skips those already submitted in previous runs (state file).
4. Sends hashes and IPs in separate batches with `addToBlocklist`.
5. Updates the state file only for successful batches: failures are retried on the next run.

The client handles rate limiting (HTTP 429) with progressive retries and a short pause between batches.

## Scheduled execution

Example of an hourly cron job with MISP:

```cron
0 * * * * cd /opt/gz-ioc && . ./.env && python gz_ioc_connector.py --source misp --misp-last 1d >> gz_ioc.log 2>&1
```

The exit code is `0` on success, `1` if some batches failed, and `2` if GravityZone credentials are missing.

## Security

- Credentials are read from environment variables only.
- Keep the `.env` file out of the repository and use a dedicated API key with only the **Incidents** area enabled.
- Imported IOCs are applied as blocking rules: use trusted sources and verify the created rules in a test company before extending them.

## Repository files

```
gz_ioc_connector.py   # the connector
requirements.txt      # dependencies
README.md             # Italian documentation
README.en.md          # this file
.gitignore            # excludes state, output and .env
```

Recommended `.gitignore`:

```
gz_ioc_state.json
iocs_not_pushed.csv
.env
__pycache__/
```

## Known limitations

- Domains and URLs are not submitted (a limitation of the `addToBlocklist` API).
- Supported hashes are MD5 and SHA-256.
- IP rules always use `protocol: any` and `direction: both`, with no port filtering (`portRange`).
- Automatic removal of expired IOCs (`removeFromBlocklist`) is not implemented.

## References

- GravityZone Public API documentation: **Incidents** section (`addToBlocklist`, `getBlocklistItems`, `removeFromBlocklist`)
- GravityZone guide: **Blocklist** section (hash, path and connection rules)

## License

Add your chosen license here (for example MIT).
