# Phase 2 Remaining — Build Plan

Execute in batches, highest impact first.

## Batch A: Net-New Detection Modules
1. WAF detection + bypass (wafw00f, per-vendor payloads)
2. SSRF probe module (cloud metadata, interactsh OOB)
3. Content discovery (multi-wordlist ffuf cascade)
4. CORS misconfiguration tester
5. Subdomain takeover checker
6. LFI payload probe

## Batch B: Intel + Scheduler
7. Version-aware exploit matching
8. Scan duration tracking + progress
9. Notify alerts on critical findings

## Batch C: Reports + Polish
10. HTML report (tera template)
11. SARIF output
12. Adaptive rate limiting

## Batch D: Monitoring + Deploy
13. Continuous monitoring mode
14. Dockerfile
