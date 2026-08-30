# LinkedIn launch post

What if your certificate-renewal job succeeds—but your live service keeps serving the old certificate?

That failure can stay invisible until customers see a browser warning or the certificate expires.

I built **TLS Sentinel** to verify the outcome that actually matters: the certificate presented by the live endpoint.

Instead of trusting renewal-job status alone, TLS Sentinel performs real TLS handshakes against a YAML inventory and records what clients receive. It reports expiration, issuer, subject, SANs, serial number, SHA-256 fingerprint, hostname validation, and scan failures.

It also keeps local fingerprint history, so it can detect when a certificate changes—and warn when the same certificate remains in place near expiration.

The MVP includes:

- Concurrent TLS endpoint scanning
- Configurable warning and critical thresholds
- Fingerprint-change history
- Generic webhook alerts
- Prometheus-compatible metrics
- CLI and HTTP health/readiness endpoints
- Docker and Kubernetes packaging
- GitHub Actions CI
- Integration tests using local certificates and TLS endpoints

The key distinction is simple:

**Renewal monitoring asks:** Did the automation run successfully?

**TLS Sentinel asks:** Did the live service actually start serving the expected result?

I designed the default service cadence around a 15-minute safety-net scan, with the option to run an immediate CLI verification from a Certbot deploy hook or deployment pipeline. Prometheus alert examples use persistence windows so transient failures do not immediately become notifications.

This is intentionally an MVP. It does not yet provide CA-chain validation, multi-region probing, alert deduplication, or multi-replica history storage. Those limitations—and the security considerations—are documented rather than hidden behind production claims.

Building TLS Sentinel reinforced an operations principle I keep coming back to:

**A successful process is not the same as a verified outcome.**

For the DevOps and sysadmin folks here: how do you currently verify that a renewed certificate reached every proxy, ingress, load balancer, or application instance?

#DevOps #SysAdmin #TLS #Observability #Python #Prometheus #SRE #Cybersecurity
