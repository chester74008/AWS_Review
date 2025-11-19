# AWS Security Review - CIS Benchmark Automation

This project automates AWS security reviews based on the **CIS Amazon Web Services Foundations Benchmark v5.0.0**.

## Overview

The CIS AWS Foundations Benchmark provides prescriptive guidance for configuring security options for AWS. This project helps automate the auditing of AWS accounts against these benchmarks.

## Benchmark Coverage

- **Total Controls**: 72 recommendations
- **Level 1 (Basic security)**: 50 controls
- **Level 2 (Advanced security)**: 31 controls

### Control Categories

1. **Identity and Access Management (IAM)** - 21 controls
2. **Storage (S3, RDS, EFS)** - 10 controls
3. **Logging and Monitoring (CloudTrail, Config, VPC)** - 20 controls
4. **Monitoring and Alerting** - 15 controls
5. **Networking** - 6 controls

## Project Structure

```
AWS_Review/
├── Benchmarks/               # CIS benchmark documents
│   └── v5.0.0/
├── scripts/                  # Automation scripts
│   ├── collectors/          # AWS CLI data collection scripts
│   ├── analyzers/           # Analysis and compliance checking
│   └── reporters/           # Report generation
├── config/                   # Configuration files
├── reports/                  # Generated audit reports
└── cis_aws_controls.json    # Parsed benchmark controls
```

## Requirements

- AWS CLI v2
- Python 3.8+
- Required Python packages:
  - boto3
  - pandas
  - openpyxl

## Usage

### 1. Configure AWS Credentials

```bash
aws configure
```

### 2. Run Full Audit

```bash
python scripts/run_audit.py --profile default --level 1
```

### 3. Run Specific Control Category

```bash
python scripts/run_audit.py --category iam --profile default
```

## Automation Capabilities

### Fully Automated (via AWS CLI/API)
- IAM user credential reports
- Access key rotation checks
- MFA status verification
- S3 bucket encryption and policies
- CloudTrail configuration
- VPC Flow Logs status
- And many more...

### Manual/Partial Automation
- Contact information verification (AWS Console only)
- Hardware MFA verification (requires additional validation)
- Macie configuration (API available but complex)

## Next Steps

1. Implement data collectors for each control category
2. Build compliance analyzers
3. Create reporting templates
4. Add support for multiple AWS accounts/profiles
5. Implement remediation suggestions
