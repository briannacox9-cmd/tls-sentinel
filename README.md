# TLS Sentinel

TLS Sentinel verifies the certificate that a live service is **actually serving**.

A certificate-renewal job can exit successfully while a reverse proxy, load balancer, ingress controller, or long-running process continues to present the old certificate. Monitoring the job proves that automation ran; it does not prove that clients receive the renewed certificate. TLS Sentinel closes that gap with real TLS handshakes, fingerprint history, expiry alerts, and Prometheus metrics.

## What the MVP does

- Loads a YAML endpoint inventory with names, hostnames, ports, and per-endpoint thresholds.
- Scans endpoints concurrently using real TCP and TLS handshakes (TLS 1.2 or newer).
- Reports expiry, days remaining, issuer, subject, DNS SANs, serial number, SHA-256 fingerprint, hostname validity, and errors.
- Appends every scan to a local JSON Lines history file and detects fingerprint changes.
- Flags a fingerprint that remains unchanged during the configured near-expiry window.
- Sends a generic JSON webhook for expiry thresholds, hostname mismatches, scan failures, and unchanged-near-expiry certificates.
- Offers one-shot CLI scans plus a scheduled service with `/healthz`, `/readyz`, and Prometheus-compatible `/metrics`.
- Emits structured JSON logs to stderr.

## Architecture

```text
YAML inventory
      │
      ▼
concurrent TLS handshakes ──► certificate parsing + hostname check
      │                                  │
      ├──► JSONL history ──► fingerprint change/unchanged detection
      │
      ├──► webhook events
      └──► current Prometheus metrics + health endpoints
```

The scanner deliberately retrieves the presented leaf certificate even when it is self-signed or mismatched, then reports hostname validity separately. That makes failure details observable and keeps local-certificate tests deterministic. TLS Sentinel does not currently perform CA-chain trust validation; see [Limitations](#limitations).

## Quick start

Python 3.11 or newer is required.

```bash
cd tls-sentinel
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
cp config.example.yaml config.yaml
tls-sentinel validate --config config.yaml
tls-sentinel scan --config config.yaml
```

Machine-readable output:

```bash
tls-sentinel scan --config config.yaml --json
```

Run the scheduled scanner and HTTP surface:

```bash
tls-sentinel serve --config config.yaml
curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:8080/readyz
curl http://127.0.0.1:8080/metrics
```

`scan` exits `0` when every handshake succeeds and every hostname matches, `1` for an operational scan failure/mismatch, and `2` for CLI or configuration errors. Expiry warnings are represented as alerts but do not change the exit code.

## Configuration

```yaml
timeout: 5s
history_file: ./data/history.jsonl

defaults:
  warning_days: 30
  critical_days: 7
  unchanged_days: 14

webhook:
  url: "https://alerts.example.net/hooks/tls-sentinel"
  timeout: 5s

server:
  listen: "0.0.0.0:8080"
  scan_interval: 5m

endpoints:
  - name: production-api
    hostname: api.example.com
    port: 443
    thresholds:
      warning_days: 21
      critical_days: 7
      unchanged_days: 10
  - name: customer-portal
    hostname: portal.example.com
    port: 443
```

Zero-day thresholds are valid and mean “alert only at or after expiration” for expiry thresholds. Endpoint names must be unique. Relative history paths resolve from the process working directory. An empty webhook URL disables webhook delivery.

`unchanged_days` is the renewal-verification window. After at least one prior successful observation, TLS Sentinel raises `certificate_unchanged` when the same SHA-256 fingerprint is still served at or below that many days remaining. A changed fingerprint is recorded in the result and increments the in-process change metric.

## Example output

```text
NAME            ENDPOINT             DAYS  HOSTNAME  CHANGED  STATUS
production-api  api.example.com:443  18.6  True      False    ok
customer-portal portal.example.com:443 42.1 True      True     ok

2 endpoint(s), 1 alert(s)
```

Each webhook request contains all events from a scan:

```json
{
  "source": "tls-sentinel",
  "events": [
    {
      "type": "certificate_unchanged",
      "severity": "warning",
      "message": "certificate fingerprint remains unchanged near expiration",
      "endpoint": "production-api",
      "observed_at": "2026-08-30T12:00:00+00:00",
      "result": {"sha256_fingerprint": "...", "days_remaining": 9.4}
    }
  ]
}
```

Webhook failures are logged but do not stop scanning or the metrics server.

## Prometheus metrics

- `tls_sentinel_scan_success`
- `tls_sentinel_hostname_valid`
- `tls_sentinel_certificate_days_remaining`
- `tls_sentinel_certificate_expiry_timestamp_seconds`
- `tls_sentinel_certificate_fingerprint_info`
- `tls_sentinel_certificate_changes_total`

Labels contain endpoint name, hostname, and port. The fingerprint appears only on the info metric to avoid multiplying every metric series.

[`examples/prometheus-alerts.yml`](examples/prometheus-alerts.yml) provides starting alert rules with `for` periods that suppress transient failures. Tune the thresholds, routing, grouping, and repeat intervals to match your renewal process and incident policy before production use.

## Docker

```bash
docker build -t tls-sentinel:0.1.0 .
docker run --rm -p 8080:8080 \
  -v "$PWD/config.yaml:/app/config.yaml:ro" \
  -v tls-sentinel-data:/data \
  tls-sentinel:0.1.0
```

The image runs as a non-root user and persists history under `/data`. The included Kubernetes manifests use a read-only root filesystem, dropped capabilities, health probes, resource bounds, a ConfigMap, and a persistent volume claim:

```bash
kubectl apply -f k8s/configmap.yaml -f k8s/deployment.yaml
```

Replace the example endpoint and image reference before applying. Store a webhook-bearing configuration as a Kubernetes Secret rather than committing it to the ConfigMap.

## Development and verification

```bash
make lint
make test
make smoke
make build
```

The integration-style tests create ephemeral self-signed certificates and local TLS listeners. They do not depend on public internet services. The smoke test exercises a real local TLS scan, history persistence, service startup, readiness, and metrics. GitHub Actions repeats compilation, tests, package creation, and a Docker build.

## Security considerations

- Treat webhook URLs as secrets; they often embed credentials. Keep them out of version control and restrict configuration-file permissions.
- The inventory controls outbound TCP connections. Only trusted operators should edit it, especially in networks where server-side request forgery is a concern.
- `/metrics` reveals hostnames, ports, certificate fingerprints, and operational state. Bind to a private interface or protect access at a reverse proxy/network-policy layer.
- History files contain operational metadata and are created with owner-only permissions when TLS Sentinel creates them. Back them up if fingerprint continuity matters.
- The scanner requires TLS 1.2 or newer and never transmits application data after the handshake.
- Webhooks use the URL exactly as configured. Use HTTPS and a receiver that authenticates requests at the network or URL-token layer; payload signing is not yet implemented.

## Limitations

- The MVP validates DNS/IP identity against SANs (with common-name fallback for legacy certificates) but does not validate the certificate chain against a CA trust store or report intermediate-chain details.
- History is append-only JSONL with no built-in retention or compaction.
- Webhook alerts are not deduplicated, retried, signed, or rate-limited; every qualifying scan can emit an event.
- The fingerprint-change counter is process-local, while full change evidence remains in the history file.
- A single replica should own a history file. Multi-replica coordination and shared databases are outside this MVP.
- TLS endpoints requiring client certificates are not supported.

## Roadmap

- CA-chain verification and intermediate-chain visibility.
- Alert deduplication, retry/backoff, payload signing, and recovery notifications.
- History retention plus SQLite/PostgreSQL backends for multi-instance operation.
- mTLS endpoint support and configurable TLS policy checks.
- Prometheus alert-rule and Grafana dashboard examples.
- SNI overrides for endpoints addressed through private IPs or load-balancer nodes.

## Renewal verification versus job monitoring

A successful ACME client, cron job, or Kubernetes Certificate resource says a certificate was obtained or stored. It cannot prove that every serving component reloaded it. TLS Sentinel observes the client-facing boundary: it connects to the configured hostname and port, captures the leaf certificate, compares its fingerprint with prior scans, and alerts when the old identity remains close to expiry. The two signals are complementary—job monitoring explains the control plane, while TLS Sentinel verifies the live data plane.

## License

MIT. See [LICENSE](LICENSE).
