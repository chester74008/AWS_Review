# AWS Security Review - CIS Benchmark Automation

Automate AWS security reviews based on the **CIS Amazon Web Services Foundations Benchmark v5.0.0**.

## Quick Start

```bash
# 1. Verify setup
python test_setup.py

# 2. Run full audit
python scripts/run_audit.py --category all --profile default

# 3. View results
python -m json.tool reports/audit_*/audit_summary.json
```

See [docs/guides/QUICKSTART.md](docs/guides/QUICKSTART.md) for detailed setup instructions.

## Current Capabilities

**30 Automated Compliance Checks** (42% coverage of CIS controls)

| Section | Checks | Status |
|---------|--------|--------|
| IAM (Identity & Access) | 13 | ✅ Complete |
| Storage (S3, RDS, EFS) | 9 | ✅ Complete |
| Logging (CloudTrail, Config, VPC) | 8 | ✅ Complete |
| Monitoring (CloudWatch) | 0 | ⚠️ Planned |
| Networking (VPC, Security Groups) | 0 | ⚠️ Planned |

## Project Structure

```
AWS_Review/
├── README.md                      # This file
├── requirements.txt               # Python dependencies
├── test_setup.py                  # Environment verification
├── cis_aws_controls.json          # Parsed CIS controls (72 total)
│
├── scripts/
│   ├── run_audit.py               # Main orchestrator
│   ├── collectors/                # AWS data collection
│   │   ├── iam_collector.py       # IAM data
│   │   ├── storage_collector.py   # S3, RDS, EFS data
│   │   └── logging_collector.py   # CloudTrail, Config, VPC data
│   └── analyzers/                 # Compliance analysis
│       ├── iam_analyzer.py        # 13 IAM checks
│       ├── storage_analyzer.py    # 9 storage checks
│       └── logging_analyzer.py    # 8 logging checks
│
├── config/                        # Configuration files
│   └── config.example.json        # Example config
│
├── reports/                       # Generated audit reports (git-ignored)
│   └── audit_TIMESTAMP/
│       ├── audit_summary.json                # Overall compliance summary
│       ├── audit_all_findings.csv            # All findings (CSV)
│       ├── audit_failures_only.csv           # Failures only (CSV)
│       ├── iam_compliance_report.json        # IAM findings (JSON)
│       ├── iam_compliance_report.csv         # IAM findings (CSV)
│       ├── storage_compliance_report.json    # Storage findings (JSON)
│       ├── storage_compliance_report.csv     # Storage findings (CSV)
│       ├── logging_compliance_report.json    # Logging findings (JSON)
│       └── logging_compliance_report.csv     # Logging findings (CSV)
│
├── docs/                          # Documentation
│   ├── guides/                    # User guides
│   │   ├── QUICKSTART.md          # 5-minute setup
│   │   ├── TESTING_GUIDE.md       # Comprehensive testing
│   │   ├── TESTING_STEPS.txt      # Step-by-step tests
│   │   └── USAGE.md               # Complete usage guide
│   │
│   ├── reference/                 # Reference documentation
│   │   ├── AWS_PERMISSIONS_REQUIRED.md  # Required AWS permissions
│   │   ├── COMMON_ERRORS.md       # Error troubleshooting
│   │   ├── QUICK_REFERENCE.md     # Command cheat sheet
│   │   ├── SECTIONS_OVERVIEW.md   # All 72 CIS controls
│   │   └── GIT_WORKFLOW.md        # Git commands
│   │
│   ├── FIXES_AND_IMPROVEMENTS.md  # Development history
│   ├── WHATS_NEW.md               # Release notes
│   └── PROJECT_SUMMARY.md         # Project overview
│
└── Benchmarks/                    # CIS benchmark documents
    └── CIS_AWS_v5.0.0.*           # PDF and XLSX versions
```

## Requirements

- **AWS CLI v2** - [Installation Guide](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
- **Python 3.8+**
- **AWS Account Permissions**: `SecurityAudit` + `ViewOnlyAccess` (see [AWS_PERMISSIONS_REQUIRED.md](docs/reference/AWS_PERMISSIONS_REQUIRED.md))

### Python Dependencies

```bash
pip install -r requirements.txt
```

Required packages:
- pandas
- openpyxl

## Usage

### Quick Commands

```bash
# Run all sections (IAM + Storage + Logging)
python scripts/run_audit.py --category all --profile default

# Run specific section
python scripts/run_audit.py --category iam --profile default
python scripts/run_audit.py --category storage --profile default
python scripts/run_audit.py --category logging --profile default

# Scan all regions (slow - 10-20 minutes)
python scripts/run_audit.py --category all --profile default --all-regions
```

### View Results

```bash
# View JSON summary
python -m json.tool reports/audit_*/audit_summary.json

# View detailed findings (JSON)
python -m json.tool reports/audit_*/iam_compliance_report.json
python -m json.tool reports/audit_*/storage_compliance_report.json
python -m json.tool reports/audit_*/logging_compliance_report.json

# Open CSV reports in Excel
# All findings across all sections
reports/audit_*/audit_all_findings.csv

# Failures only, sorted by severity
reports/audit_*/audit_failures_only.csv

# Individual section CSVs
reports/audit_*/iam_compliance_report.csv
reports/audit_*/storage_compliance_report.csv
reports/audit_*/logging_compliance_report.csv
```

See [docs/reference/QUICK_REFERENCE.md](docs/reference/QUICK_REFERENCE.md) for all commands.

## Example Output

```
================================================================================
AUDIT SUMMARY
================================================================================
Overall Compliance: 65.45%
Total Checks: 30

IAM:
  Compliance: 69.23%
  Passed: 9/13
  Failed: 4

Storage:
  Compliance: 66.67%
  Passed: 6/9
  Failed: 3

Logging:
  Compliance: 62.50%
  Passed: 5/8
  Failed: 3
```

## Documentation

### Getting Started
- [QUICKSTART.md](docs/guides/QUICKSTART.md) - 5-minute setup and first run
- [TESTING_GUIDE.md](docs/guides/TESTING_GUIDE.md) - Comprehensive testing instructions
- [USAGE.md](docs/guides/USAGE.md) - Complete usage guide

### Reference
- [AWS_PERMISSIONS_REQUIRED.md](docs/reference/AWS_PERMISSIONS_REQUIRED.md) - Required AWS permissions
- [COMMON_ERRORS.md](docs/reference/COMMON_ERRORS.md) - Troubleshooting guide
- [QUICK_REFERENCE.md](docs/reference/QUICK_REFERENCE.md) - Command cheat sheet
- [SECTIONS_OVERVIEW.md](docs/reference/SECTIONS_OVERVIEW.md) - All 72 CIS controls

### Development
- [WHATS_NEW.md](docs/WHATS_NEW.md) - Release notes and new features
- [FIXES_AND_IMPROVEMENTS.md](docs/FIXES_AND_IMPROVEMENTS.md) - Development history
- [GIT_WORKFLOW.md](docs/reference/GIT_WORKFLOW.md) - Git workflow guide

## Troubleshooting

### Common Issues

**Error: "The config profile (X) could not be found"**
- Check available profiles: `aws configure list-profiles`
- Create profile: `aws configure --profile default`

**Error: "AccessDenied"**
- Add AWS managed policies: `SecurityAudit` + `ViewOnlyAccess`
- See [AWS_PERMISSIONS_REQUIRED.md](docs/reference/AWS_PERMISSIONS_REQUIRED.md)

**Empty data collected**
- Verify AWS credentials: `aws sts get-caller-identity --profile default`
- Check for typos in profile name
- Verify resources exist in your account

See [COMMON_ERRORS.md](docs/reference/COMMON_ERRORS.md) for complete troubleshooting guide.

## Roadmap

### Implemented
- ✅ IAM Analyzer (13 checks)
- ✅ Storage Analyzer (9 checks)
- ✅ Logging Analyzer (8 checks)
- ✅ Multi-region support
- ✅ JSON reporting
- ✅ CSV export (Excel-ready)

### Coming Soon
- ⚠️ CloudWatch Monitoring Analyzer (15 checks)
- ⚠️ Networking Analyzer (9 checks)
- ⚠️ HTML/PDF report generation
- ⚠️ Auto-remediation framework

See [FIXES_AND_IMPROVEMENTS.md](docs/FIXES_AND_IMPROVEMENTS.md) for detailed roadmap.

## Security Note

**Important:** This tool is READ-ONLY and only collects information. It does not make changes to your AWS account.

Audit reports are stored in `reports/` directory and are **excluded from git** via `.gitignore` to protect your sensitive data.

## Repository

**GitHub:** https://github.com/chester74008/AWS_Review.git

## License

This project is for internal security auditing purposes.
