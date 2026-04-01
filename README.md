# Cloud Security Dashboard 🛡️

**Nivedhitha KS | Cybersecurity Portfolio**

A real-time AWS cloud security posture monitoring dashboard that detects and visualises misconfigurations across IAM, S3, and EC2 Security Groups — aligned to the CIS AWS Benchmark.

## 🔴 Live Demo
> Deploy link goes here after Render deployment

## What It Does

| Module | What It Checks |
|---|---|
| **IAM** | Root access keys, MFA gaps, wildcard policies, dormant credentials |
| **S3** | Public bucket exposure, missing encryption, disabled versioning, no access logs |
| **Security Groups** | SSH/RDP open to internet, database ports exposed, unused groups |
| **Threat Feed** | Brute force, S3 exfiltration, IAM anomalies, port scans, crypto mining |

## Key Features
- CIS AWS Benchmark compliance scoring
- Severity classification: CRITICAL / HIGH / MEDIUM / LOW
- One-click remediation steps for every finding
- Real-time threat event timeline
- REST API — all data available at `/api/all`, `/api/iam`, `/api/s3`, `/api/sg`, `/api/threats`

## Tech Stack
- **Backend**: Python 3, Flask
- **Frontend**: Vanilla JS, CSS Grid, Google Fonts
- **Deployment**: Render (free tier)

Live demo:https://cloud-security-dashboard.onrender.com/
```

## What to Tell Recruiters

> "I built a cloud security posture management dashboard that simulates AWS security monitoring. It checks IAM misconfigurations, S3 bucket exposure, security group rules, and displays a real-time threat feed — all mapped to CIS AWS Benchmark controls. Built with Python and Flask, deployed live on Render."

## CIS AWS Benchmark Controls Covered
- CIS 1.3 — Inactive credentials
- CIS 1.4 — Root access keys
- CIS 1.10 — MFA on console users
- CIS 1.11 — Password rotation
- CIS 1.16 — Least privilege policies
- CIS 2.1 — S3 public access
- CIS 4.1 — SSH not open to world
- CIS 4.2 — RDP not open to world

---
*Part of a 6-project cybersecurity portfolio. Day 15 of 60-day security journey.*
