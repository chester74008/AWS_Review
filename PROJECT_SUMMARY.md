# AWS Review Project - Summary

## Project Overview

This project automates security reviews of AWS accounts based on the **CIS Amazon Web Services Foundations Benchmark v5.0.0**. It's designed to help security teams and administrators quickly assess their AWS environment's compliance with industry best practices.

## What We've Built

### 1. Benchmark Analysis
- Parsed the CIS AWS Benchmark (PDF and XLSX formats)
- Extracted **72 security controls** across 5 main categories
- Created structured JSON representation ([cis_aws_controls.json](cis_aws_controls.json))

### 2. Automated Data Collectors (AWS CLI-based)

#### IAM Collector ([scripts/collectors/iam_collector.py](scripts/collectors/iam_collector.py))
Collects Identity and Access Management data:
- User credentials and access keys
- Password policies
- MFA device status
- Policy attachments
- IAM Access Analyzer status
- SSL/TLS certificates
- Support role configuration

**CIS Controls Covered:** 1.3, 1.4, 1.6, 1.7, 1.8, 1.9, 1.10, 1.11, 1.12, 1.13, 1.14, 1.15, 1.16, 1.18, 1.19, 1.21

#### Storage Collector ([scripts/collectors/storage_collector.py](scripts/collectors/storage_collector.py))
Collects S3, RDS, and EFS configuration:
- S3 bucket policies and encryption
- S3 versioning and MFA Delete
- S3 Block Public Access settings
- RDS instance encryption and accessibility
- RDS auto minor version upgrade status
- EFS encryption status
- Macie configuration

**CIS Controls Covered:** 2.1.1, 2.1.2, 2.1.3, 2.1.4, 2.2.1, 2.2.2, 2.2.3, 2.2.4, 2.3.1

#### Logging Collector ([scripts/collectors/logging_collector.py](scripts/collectors/logging_collector.py))
Collects logging and monitoring configuration:
- CloudTrail trails and configuration
- AWS Config recorders and delivery channels
- VPC Flow Logs
- KMS key rotation status
- CloudWatch Log Groups and Metric Filters
- CloudWatch Alarms

**CIS Controls Covered:** 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 4.x

### 3. Compliance Analyzers

#### IAM Analyzer ([scripts/analyzers/iam_analyzer.py](scripts/analyzers/iam_analyzer.py))
Analyzes IAM data against CIS controls:
- Validates password policies
- Checks for unused credentials
- Verifies MFA enforcement
- Identifies overly permissive policies
- Validates access key rotation
- Reports findings with severity levels (CRITICAL, HIGH, MEDIUM, LOW)

### 4. Orchestration Script

#### Main Audit Runner ([scripts/run_audit.py](scripts/run_audit.py))
- Orchestrates all collectors and analyzers
- Supports single or multi-region audits
- Generates compliance reports
- Provides summary dashboard
- Command-line interface for easy execution

## Project Structure

```
AWS_Review/
├── README.md                          # Project overview
├── USAGE.md                           # Detailed usage instructions
├── PROJECT_SUMMARY.md                 # This file
├── requirements.txt                   # Python dependencies
├── .gitignore                         # Git ignore rules
│
├── Benchmarks/                        # CIS benchmark documents
│   └── v5.0.0/
│       ├── CIS_*.pdf                 # Official benchmark PDF
│       └── CIS_*.xlsx                # Benchmark spreadsheet
│
├── cis_aws_controls.json             # Parsed controls (72 controls)
│
├── config/                           # Configuration files
│   └── config.example.json           # Sample configuration
│
├── scripts/                          # Automation scripts
│   ├── run_audit.py                  # Main orchestrator
│   │
│   ├── collectors/                   # Data collectors
│   │   ├── iam_collector.py         # IAM data collection
│   │   ├── storage_collector.py     # S3/RDS/EFS collection
│   │   └── logging_collector.py     # CloudTrail/Config/VPC logs
│   │
│   ├── analyzers/                    # Compliance analyzers
│   │   └── iam_analyzer.py          # IAM compliance analysis
│   │
│   └── reporters/                    # Report generators (future)
│
└── reports/                          # Generated audit reports
    └── audit_TIMESTAMP/
        ├── audit_summary.json
        ├── iam_data.json
        ├── iam_compliance_report.json
        ├── storage_data.json
        └── logging_data.json
```

## What Can Be Automated vs. Manual

### ✅ Fully Automated (via AWS CLI)

**IAM (13 controls):**
- Root account security (access keys, MFA)
- Password policies (length, reuse)
- User MFA enforcement
- Credential age and rotation
- Permission assignments
- Policy analysis
- Access Analyzer status

**Storage (9 controls):**
- S3 bucket security (encryption, public access, policies)
- RDS security (encryption, public access, patching)
- EFS encryption

**Logging (10+ controls):**
- CloudTrail configuration
- AWS Config status
- VPC Flow Logs
- KMS key rotation
- CloudWatch logging

### ⚠️ Manual/Semi-Automated

**Require Console Access:**
- 1.1 - Contact details verification
- 1.2 - Security contact information
- 1.5 - Hardware MFA verification

**Complex/Multi-step:**
- 1.20 - Centralized IAM (multi-account environments)
- 2.1.3 - Macie job configuration
- 4.x - Some CloudWatch metric filter patterns

## How to Use

### Quick Start

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure AWS credentials:**
   ```bash
   aws configure
   ```

3. **Run full audit:**
   ```bash
   python scripts/run_audit.py --profile default
   ```

### Example Commands

```bash
# IAM only
python scripts/run_audit.py --category iam --profile myprofile

# All regions (slower but comprehensive)
python scripts/run_audit.py --all-regions --profile production

# Individual collector
python scripts/collectors/iam_collector.py --profile default --output iam_data.json

# Analyze collected data
python scripts/analyzers/iam_analyzer.py --input iam_data.json --output report.json
```

See [USAGE.md](USAGE.md) for detailed instructions.

## AWS Permissions Required

The scripts need **read-only** permissions. Recommended policy:

```json
{
  "Effect": "Allow",
  "Action": [
    "iam:Get*", "iam:List*", "iam:GenerateCredentialReport",
    "s3:GetBucket*", "s3:ListAllMyBuckets",
    "rds:Describe*", "efs:Describe*",
    "cloudtrail:Describe*", "cloudtrail:Get*", "cloudtrail:List*",
    "config:Describe*", "ec2:Describe*",
    "kms:Describe*", "kms:Get*", "kms:List*",
    "logs:Describe*", "cloudwatch:Describe*",
    "accessanalyzer:List*", "macie2:Get*"
  ],
  "Resource": "*"
}
```

## Current Implementation Status

### ✅ Completed
- [x] Parse CIS benchmark (XLSX → JSON)
- [x] IAM data collector (all IAM controls)
- [x] Storage data collector (S3, RDS, EFS)
- [x] Logging data collector (CloudTrail, Config, VPC)
- [x] IAM compliance analyzer (13 controls)
- [x] Main orchestration script
- [x] Documentation (README, USAGE)
- [x] Project structure

### 🚧 To Be Implemented
- [ ] Storage compliance analyzer
- [ ] Logging compliance analyzer
- [ ] Monitoring/Alerting analyzer (Section 4)
- [ ] Networking analyzer (Section 5)
- [ ] HTML/PDF report generation
- [ ] Auto-remediation framework
- [ ] Multi-account support
- [ ] CI/CD integration examples
- [ ] Notification system (email/SNS)

## Key Features

1. **AWS CLI-Based**: Uses native AWS CLI commands for maximum compatibility
2. **Modular Design**: Separate collectors and analyzers for each service
3. **Multi-Region Support**: Can audit across all AWS regions
4. **Detailed Reporting**: JSON reports with severity levels
5. **CIS Compliance Mapping**: Every check maps to specific CIS control
6. **Extensible**: Easy to add new controls and checks

## Use Cases

1. **Security Audits**: Periodic compliance reviews
2. **Client Assessments**: Review customer AWS environments
3. **Continuous Monitoring**: Scheduled automated scans
4. **Remediation Tracking**: Before/after comparisons
5. **Compliance Reporting**: Evidence for auditors

## Next Steps for Development

1. **Complete Analyzers**: Implement storage and logging analyzers
2. **Report Templates**: Create HTML/PDF report generators
3. **Dashboard**: Build web-based compliance dashboard
4. **Remediation**: Add automated fix capabilities
5. **Multi-Account**: Support AWS Organizations
6. **Integration**: CI/CD pipeline examples (GitHub Actions, GitLab CI)

## Comparison to Similar Projects

This project is similar to tools like:
- **AWS Security Hub**: But more focused on CIS benchmark
- **Prowler**: Open-source AWS security tool (bash-based)
- **ScoutSuite**: Multi-cloud security auditing
- **CloudSploit**: Automated security scanning

**Our Advantages:**
- Python-based (easier to extend)
- Modular architecture
- Focused on CIS benchmark
- Designed for client assessments

## Contributing

To add new controls:

1. Update appropriate collector in `scripts/collectors/`
2. Add analysis logic in `scripts/analyzers/`
3. Map to CIS control number
4. Add to documentation

## References

- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [AWS CLI Reference](https://docs.aws.amazon.com/cli/latest/reference/)
- [AWS Security Best Practices](https://aws.amazon.com/security/best-practices/)
- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/)

---

**Project Created:** 2024-01-14
**CIS Benchmark Version:** v5.0.0
**Python Version:** 3.8+
**AWS CLI Version:** 2.x
