# ============================================================
# Cloud Security Dashboard — Flask Backend
# Nivedhitha KS | Cybersecurity Portfolio
# Simulates AWS security posture monitoring
# ============================================================

from flask import Flask, render_template, jsonify
import datetime
import random
import json

app = Flask(__name__)

# ── Simulated AWS Security Data ──────────────────────────────

def get_iam_findings():
    return [
        {
            "id": "IAM-001",
            "severity": "CRITICAL",
            "resource": "arn:aws:iam::123456789012:user/admin-backup",
            "issue": "Root account has active access keys",
            "detail": "AWS root account access keys are active. This violates CIS AWS Benchmark 1.4.",
            "remediation": "Delete root access keys. Use IAM roles instead.",
            "cis_control": "CIS 1.4",
            "status": "OPEN"
        },
        {
            "id": "IAM-002",
            "severity": "HIGH",
            "resource": "arn:aws:iam::123456789012:user/developer-john",
            "issue": "MFA not enabled for console user",
            "detail": "IAM user with console access has no MFA device attached.",
            "remediation": "Enforce MFA using IAM policy condition aws:MultiFactorAuthPresent.",
            "cis_control": "CIS 1.10",
            "status": "OPEN"
        },
        {
            "id": "IAM-003",
            "severity": "HIGH",
            "resource": "arn:aws:iam::123456789012:policy/DevFullAccess",
            "issue": "Policy grants wildcard (*) permissions on all resources",
            "detail": "Custom policy allows Action: '*' on Resource: '*'. Violates least-privilege principle.",
            "remediation": "Replace wildcard with specific actions and resource ARNs.",
            "cis_control": "CIS 1.16",
            "status": "OPEN"
        },
        {
            "id": "IAM-004",
            "severity": "MEDIUM",
            "resource": "arn:aws:iam::123456789012:user/old-contractor",
            "issue": "Access key unused for 90+ days",
            "detail": "Access key AKIA3XAMPLE last used 127 days ago. Dormant credentials are an attack surface.",
            "remediation": "Disable or delete unused access keys after 90 days.",
            "cis_control": "CIS 1.3",
            "status": "OPEN"
        },
        {
            "id": "IAM-005",
            "severity": "LOW",
            "resource": "arn:aws:iam::123456789012:user/service-account-ci",
            "issue": "No password rotation policy set",
            "detail": "Account password policy does not enforce rotation. Passwords may be over 1 year old.",
            "remediation": "Set IAM password policy with MaxPasswordAge: 90.",
            "cis_control": "CIS 1.11",
            "status": "RESOLVED"
        },
    ]

def get_s3_findings():
    return [
        {
            "id": "S3-001",
            "severity": "CRITICAL",
            "bucket": "prod-customer-data-backup",
            "region": "ap-south-1",
            "issue": "Bucket is publicly readable",
            "detail": "ACL allows s3:GetObject for Principal: '*'. Anyone on the internet can read this bucket.",
            "remediation": "Remove public ACL. Enable S3 Block Public Access at account level.",
            "exposed_objects": 2847,
            "status": "OPEN"
        },
        {
            "id": "S3-002",
            "severity": "HIGH",
            "bucket": "dev-app-uploads-staging",
            "region": "us-east-1",
            "issue": "Server-side encryption disabled",
            "detail": "Bucket stores data without SSE-S3 or SSE-KMS encryption. Data at rest is unprotected.",
            "remediation": "Enable default encryption: aws s3api put-bucket-encryption",
            "exposed_objects": 0,
            "status": "OPEN"
        },
        {
            "id": "S3-003",
            "severity": "HIGH",
            "bucket": "internal-logs-archive",
            "region": "ap-south-1",
            "issue": "Bucket versioning disabled",
            "detail": "Without versioning, ransomware or accidental deletion cannot be recovered.",
            "remediation": "Enable versioning: aws s3api put-bucket-versioning --versioning-configuration Status=Enabled",
            "exposed_objects": 0,
            "status": "OPEN"
        },
        {
            "id": "S3-004",
            "severity": "MEDIUM",
            "bucket": "static-assets-cdn",
            "region": "us-east-1",
            "issue": "Access logging not enabled",
            "detail": "No access logs mean no audit trail. Cannot detect unauthorized data access.",
            "remediation": "Enable S3 server access logging to a separate logging bucket.",
            "exposed_objects": 0,
            "status": "RESOLVED"
        },
    ]

def get_sg_findings():
    return [
        {
            "id": "SG-001",
            "severity": "CRITICAL",
            "group": "sg-0abc123def (prod-web-sg)",
            "region": "ap-south-1",
            "issue": "SSH open to entire internet (0.0.0.0/0)",
            "detail": "Port 22 inbound allows all source IPs. This is the most exploited misconfiguration in AWS.",
            "remediation": "Restrict SSH to your office IP or use AWS Systems Manager Session Manager instead.",
            "port": 22,
            "status": "OPEN"
        },
        {
            "id": "SG-002",
            "severity": "CRITICAL",
            "group": "sg-0def456ghi (db-security-group)",
            "region": "ap-south-1",
            "issue": "RDP port 3389 open to 0.0.0.0/0",
            "detail": "Windows Remote Desktop accessible from anywhere. Brute-force attacks are constant on this port.",
            "remediation": "Remove 0.0.0.0/0 rule. Use VPN + specific IP allowlist only.",
            "port": 3389,
            "status": "OPEN"
        },
        {
            "id": "SG-003",
            "severity": "HIGH",
            "group": "sg-0ghi789jkl (mysql-prod)",
            "region": "us-east-1",
            "issue": "MySQL port 3306 exposed publicly",
            "detail": "Database port reachable from internet. Databases should never be directly internet-accessible.",
            "remediation": "Move RDS to private subnet. Access via application tier only.",
            "port": 3306,
            "status": "OPEN"
        },
        {
            "id": "SG-004",
            "severity": "MEDIUM",
            "group": "sg-0jkl012mno (legacy-app)",
            "region": "us-east-1",
            "issue": "Unused security group with wide-open rules",
            "detail": "Security group is not attached to any resource but still exists with permissive rules.",
            "remediation": "Delete unused security groups. Reduces blast radius if accidentally attached.",
            "port": "ALL",
            "status": "OPEN"
        },
    ]

def get_threat_events():
    now = datetime.datetime.now()
    return [
        {
            "time": (now - datetime.timedelta(minutes=3)).strftime("%H:%M:%S"),
            "type": "BRUTE_FORCE",
            "severity": "HIGH",
            "message": "412 failed SSH login attempts on ec2-13-233-xx-xx.ap-south-1.compute.amazonaws.com",
            "source_ip": "185.220.101.47",
            "geo": "Russia"
        },
        {
            "time": (now - datetime.timedelta(minutes=11)).strftime("%H:%M:%S"),
            "type": "S3_EXFIL",
            "severity": "CRITICAL",
            "message": "Unusual GetObject burst: 2,847 objects downloaded in 4 minutes from bucket prod-customer-data-backup",
            "source_ip": "103.21.244.0",
            "geo": "Unknown"
        },
        {
            "time": (now - datetime.timedelta(minutes=28)).strftime("%H:%M:%S"),
            "type": "IAM_ANOMALY",
            "severity": "HIGH",
            "message": "Root account login detected from new location. MFA challenge triggered.",
            "source_ip": "91.108.4.10",
            "geo": "Netherlands"
        },
        {
            "time": (now - datetime.timedelta(hours=1, minutes=5)).strftime("%H:%M:%S"),
            "type": "PORT_SCAN",
            "severity": "MEDIUM",
            "message": "Sequential port scan detected across 10 EC2 instances. Ports 22, 80, 443, 3306, 5432 probed.",
            "source_ip": "45.155.205.233",
            "geo": "Germany"
        },
        {
            "time": (now - datetime.timedelta(hours=2, minutes=41)).strftime("%H:%M:%S"),
            "type": "CONFIG_CHANGE",
            "severity": "MEDIUM",
            "message": "Security group sg-0abc123def modified: new inbound rule added for port 8080 from 0.0.0.0/0",
            "source_ip": "Internal",
            "geo": "Chennai, IN"
        },
        {
            "time": (now - datetime.timedelta(hours=3, minutes=17)).strftime("%H:%M:%S"),
            "type": "CRYPTO_MINING",
            "severity": "HIGH",
            "message": "EC2 instance i-0a1b2c3d CPU sustained at 98% for 90+ minutes. Possible cryptominer.",
            "source_ip": "Internal",
            "geo": "ap-south-1"
        },
    ]

def get_summary():
    iam = get_iam_findings()
    s3 = get_s3_findings()
    sg = get_sg_findings()
    all_findings = iam + s3 + sg

    return {
        "total_findings": len(all_findings),
        "critical": sum(1 for f in all_findings if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in all_findings if f["severity"] == "HIGH"),
        "medium": sum(1 for f in all_findings if f["severity"] == "MEDIUM"),
        "low": sum(1 for f in all_findings if f["severity"] == "LOW"),
        "resolved": sum(1 for f in all_findings if f.get("status") == "RESOLVED"),
        "open": sum(1 for f in all_findings if f.get("status") == "OPEN"),
        "compliance_score": 34,
        "account_id": "123456789012",
        "account_alias": "prod-main",
        "regions_scanned": ["ap-south-1", "us-east-1"],
        "last_scan": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "services_checked": ["IAM", "S3", "EC2 Security Groups", "CloudTrail", "GuardDuty"]
    }

# ── Routes ───────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/summary')
def api_summary():
    return jsonify(get_summary())

@app.route('/api/iam')
def api_iam():
    return jsonify(get_iam_findings())

@app.route('/api/s3')
def api_s3():
    return jsonify(get_s3_findings())

@app.route('/api/sg')
def api_sg():
    return jsonify(get_sg_findings())

@app.route('/api/threats')
def api_threats():
    return jsonify(get_threat_events())

@app.route('/api/all')
def api_all():
    return jsonify({
        "summary": get_summary(),
        "iam": get_iam_findings(),
        "s3": get_s3_findings(),
        "security_groups": get_sg_findings(),
        "threats": get_threat_events()
    })

if __name__ == '__main__':
    print("\n" + "="*60)
    print("  CLOUD SECURITY DASHBOARD")
    print("  Nivedhitha KS | Cybersecurity Portfolio")
    print("  Open: http://127.0.0.1:5000")
    print("="*60 + "\n")
    app.run(debug=False, host='0.0.0.0', port=5000)
