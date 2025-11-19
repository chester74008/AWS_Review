# AWS Security Review - Usage Guide

## Prerequisites

1. **AWS CLI v2** installed and configured
   ```bash
   aws --version
   ```

2. **Python 3.8+** installed
   ```bash
   python --version
   ```

3. **AWS Credentials** configured
   ```bash
   aws configure
   ```

## Installation

1. Clone or navigate to the project directory:
   ```bash
   cd AWS_Review
   ```

2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Quick Start

### Run Full Audit (All Categories)

```bash
python scripts/run_audit.py --profile default
```

### Run Specific Category

**IAM Only:**
```bash
python scripts/run_audit.py --category iam --profile default
```

**Storage Only (S3, RDS, EFS):**
```bash
python scripts/run_audit.py --category storage --profile default
```

**Logging & Monitoring:**
```bash
python scripts/run_audit.py --category logging --profile default
```

### Multi-Region Audit

By default, the audit runs in `us-east-1`. To audit across all AWS regions:

```bash
python scripts/run_audit.py --all-regions --profile default
```

**Note:** Multi-region audits take significantly longer and may incur additional AWS API costs.

## Individual Collectors

You can run individual collectors for more control:

### IAM Data Collection

```bash
python scripts/collectors/iam_collector.py --profile default --output iam_data.json
```

Then analyze the data:

```bash
python scripts/analyzers/iam_analyzer.py --input iam_data.json --output iam_report.json
```

### Storage Data Collection

```bash
python scripts/collectors/storage_collector.py --profile default --output storage_data.json
```

### Logging Data Collection

```bash
python scripts/collectors/logging_collector.py --profile default --output logging_data.json
```

## Understanding the Output

After running an audit, you'll find reports in the `reports/audit_TIMESTAMP/` directory:

```
reports/audit_20240114_120000/
├── audit_summary.json           # Overall compliance summary
├── iam_data.json                # Raw IAM data collected
├── iam_compliance_report.json   # IAM compliance findings
├── storage_data.json            # Raw storage data
└── logging_data.json            # Raw logging data
```

### Report Structure

**audit_summary.json:**
```json
{
  "audit_time": "2024-01-14T12:00:00",
  "overall_compliance_percentage": 75.5,
  "total_findings": 13,
  "by_section": {
    "IAM": {
      "total": 13,
      "passed": 10,
      "failed": 3,
      "manual": 0,
      "compliance_percentage": 76.92
    }
  }
}
```

**Compliance Reports (e.g., iam_compliance_report.json):**
```json
{
  "analysis_time": "2024-01-14T12:00:00",
  "summary": {
    "total_checks": 13,
    "passed": 10,
    "failed": 3,
    "manual": 0
  },
  "findings": [
    {
      "control": "1.3",
      "title": "Root user has active access keys",
      "status": "FAIL",
      "severity": "CRITICAL",
      "details": "Root account has active access keys...",
      "timestamp": "2024-01-14T12:00:00"
    }
  ]
}
```

## CIS Controls Coverage

### Fully Automated Controls

The following CIS controls are **fully automated** using AWS CLI:

**IAM (Section 1):**
- 1.3 - Root user access keys
- 1.4 - Root user MFA
- 1.7 - Password policy length
- 1.8 - Password reuse prevention
- 1.9 - User MFA enforcement
- 1.11 - Unused credentials
- 1.12 - Single access key per user
- 1.13 - Access key rotation
- 1.14 - Group-based permissions
- 1.15 - No full admin policies
- 1.16 - Support role exists
- 1.19 - IAM Access Analyzer
- 1.21 - CloudShell access restriction

**Storage (Section 2):**
- 2.1.1 - S3 HTTPS enforcement
- 2.1.2 - S3 MFA Delete
- 2.1.4 - S3 Block Public Access
- 2.2.1 - RDS encryption at rest
- 2.2.2 - RDS auto minor version upgrade
- 2.2.3 - RDS public accessibility
- 2.3.1 - EFS encryption

**Logging (Section 3):**
- 3.1 - CloudTrail multi-region
- 3.2 - CloudTrail log validation
- 3.3 - AWS Config enabled
- 3.5 - CloudTrail KMS encryption
- 3.6 - KMS key rotation
- 3.7 - VPC Flow Logs
- 3.8/3.9 - S3 object-level logging

### Manual/Semi-Automated Controls

Some controls require manual verification or Console access:

- 1.1 - Contact details (Console only)
- 1.2 - Security contact (Console only)
- 1.5 - Hardware MFA for root (requires verification)
- 1.20 - Centralized IAM management (multi-account setup)
- 2.1.3 - Macie configuration (complex setup)
- 4.x - CloudWatch metric filters and alarms

## AWS Permissions Required

The audit scripts require read-only permissions. Here's a minimal IAM policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:Get*",
        "iam:List*",
        "iam:GenerateCredentialReport",
        "s3:GetBucket*",
        "s3:ListAllMyBuckets",
        "rds:Describe*",
        "efs:Describe*",
        "cloudtrail:Describe*",
        "cloudtrail:Get*",
        "cloudtrail:List*",
        "config:Describe*",
        "ec2:Describe*",
        "kms:Describe*",
        "kms:Get*",
        "kms:List*",
        "logs:Describe*",
        "cloudwatch:Describe*",
        "accessanalyzer:List*",
        "macie2:Get*"
      ],
      "Resource": "*"
    }
  ]
}
```

## Troubleshooting

### "Access Denied" Errors

Ensure your AWS credentials have sufficient permissions. You can test with:

```bash
aws sts get-caller-identity
```

### No Data Collected

1. Verify AWS CLI is configured:
   ```bash
   aws configure list
   ```

2. Check if the profile exists:
   ```bash
   aws configure list-profiles
   ```

3. Test connectivity:
   ```bash
   aws iam list-users --profile YOUR_PROFILE
   ```

### Performance Issues

Multi-region audits can be slow. For faster results:
- Run single-region audits
- Use `--category` to audit specific sections
- Increase AWS API rate limits (contact AWS Support)

## Next Steps

1. Review the compliance report
2. Prioritize CRITICAL and HIGH severity findings
3. Implement remediation for failed controls
4. Re-run audit to verify fixes
5. Schedule regular automated audits (e.g., weekly/monthly)

## Contributing

To add support for additional CIS controls:

1. Add collection logic to appropriate collector (`collectors/*.py`)
2. Add analysis logic to appropriate analyzer (`analyzers/*.py`)
3. Update this documentation
4. Test with multiple AWS accounts

## References

- [CIS AWS Foundations Benchmark v5.0.0](https://www.cisecurity.org/benchmark/amazon_web_services)
- [AWS CLI Command Reference](https://docs.aws.amazon.com/cli/latest/reference/)
- [AWS Security Best Practices](https://aws.amazon.com/security/best-practices/)
