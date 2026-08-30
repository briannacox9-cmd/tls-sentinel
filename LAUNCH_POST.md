# Launch post draft

I built **TLS Sentinel**, a small open-source-style monitoring MVP for a failure mode that shows up repeatedly in DevOps and sysadmin work: the certificate-renewal job says “success,” but the live service is still serving the old certificate.

TLS Sentinel performs real concurrent TLS handshakes against a YAML inventory, reports the certificate actually presented to clients, stores fingerprint history, and alerts when certificates expire, hostnames mismatch, scans fail, or a certificate stays unchanged near expiration. It also exposes Prometheus metrics and lightweight health endpoints, runs as a non-root Docker container, and includes hardened Kubernetes manifests.

The part I care about most is the distinction between automation status and outcome verification. A successful renewal job is a control-plane signal. A handshake against the live endpoint verifies the data plane.

The repository includes local-certificate integration tests, a no-internet smoke test, GitHub Actions CI, example configuration, and documentation covering security tradeoffs and current limitations. This is an MVP, so I’ve been explicit about what it does not yet provide—such as CA-chain validation, alert deduplication, or multi-replica history storage.

If you operate TLS at a reverse proxy, ingress, CDN, or load balancer, I’d be interested to hear which reload/deployment failure modes have bitten you.

#devops #sysadmin #tls #observability #python #prometheus
