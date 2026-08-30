# LinkedIn launch post

A certificate-renewal job says “success,” everyone moves on—and the live service keeps serving the old certificate.

That is the problem behind a small project I’ve been building: **TLS Sentinel**.

It connects to real TLS endpoints and checks the certificate users are actually receiving. It reports the expiration date, issuer, subject, SANs, serial number, SHA-256 fingerprint, hostname validation, and any connection errors.

The useful part is the history. TLS Sentinel remembers certificate fingerprints, detects when they change, and warns when the same certificate is still being served close to expiration.

The MVP has:

- A YAML endpoint inventory
- Concurrent TLS scans
- Prometheus metrics
- Webhook alerts
- A CLI plus health and readiness endpoints
- Docker and Kubernetes examples
- Local-certificate integration tests
- GitHub Actions CI

The main idea is pretty simple:

**A renewal job tells you the process ran. A live handshake tells you whether the result reached users.**

The normal background interval is 15 minutes, and you can also run an immediate check from a Certbot deploy hook or deployment pipeline. I included sample Prometheus rules with persistence windows so one brief network issue does not immediately turn into an alert.

It is still an MVP. CA-chain validation, multi-region probing, alert deduplication, and shared history storage are on the roadmap—not features I’m pretending are already there.

I’d be interested to hear how other DevOps and sysadmin teams verify that renewed certificates actually reach every proxy, ingress, load balancer, and application instance.

#DevOps #SysAdmin #TLS #Observability #Python #Prometheus #SRE
