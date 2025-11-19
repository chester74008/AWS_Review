# Quick Reference Card

## 🚀 Essential Commands

### Setup and Verification

```bash
# Check AWS CLI installed
aws --version

# List available AWS profiles
aws configure list-profiles

# Verify AWS credentials work
aws sts get-caller-identity --profile default

# Run environment check
python test_setup.py
```

### Running Audits

```bash
# Full audit (all sections, single region) - RECOMMENDED
python scripts/run_audit.py --category all --profile default

# IAM only (fastest)
python scripts/run_audit.py --category iam --profile default

# Storage only
python scripts/run_audit.py --category storage --profile default

# Logging only
python scripts/run_audit.py --category logging --profile default

# All sections, all regions (slow - 10-20 minutes)
python scripts/run_audit.py --category all --profile default --all-regions

# Specific region
python scripts/run_audit.py --category all --profile default --region us-west-2
```

### Viewing Results

```bash
# List all reports
ls reports/

# View latest audit summary
python -m json.tool reports/audit_*/audit_summary.json | more

# View IAM compliance report
python -m json.tool reports/audit_*/iam_compliance_report.json | more

# View Storage compliance report
python -m json.tool reports/audit_*/storage_compliance_report.json | more

# View Logging compliance report
python -m json.tool reports/audit_*/logging_compliance_report.json | more

# View raw collected data
python -m json.tool reports/audit_*/iam_data.json | more
python -m json.tool reports/audit_*/storage_data.json | more
python -m json.tool reports/audit_*/logging_data.json | more
```

### Testing Individual Components

```bash
# Test IAM collector only
python scripts/collectors/iam_collector.py --profile default --output test_iam.json

# Test Storage collector only
python scripts/collectors/storage_collector.py --profile default --output test_storage.json

# Test Logging collector only
python scripts/collectors/logging_collector.py --profile default --output test_logging.json

# Test IAM analyzer only
python scripts/analyzers/iam_analyzer.py --input test_iam.json --output test_iam_report.json

# Test Storage analyzer only
python scripts/analyzers/storage_analyzer.py --input test_storage.json --output test_storage_report.json

# Test Logging analyzer only
python scripts/analyzers/logging_analyzer.py --input test_logging.json --output test_logging_report.json
```

### AWS CLI Test Commands

```bash
# Test IAM permissions
aws iam list-users --profile default
aws iam generate-credential-report --profile default

# Test S3 permissions
aws s3 ls --profile default
aws s3api list-buckets --profile default

# Test RDS permissions
aws rds describe-db-instances --region us-east-1 --profile default

# Test CloudTrail permissions
aws cloudtrail describe-trails --profile default

# Test Config permissions
aws configservice describe-configuration-recorders --region us-east-1 --profile default

# Test VPC permissions
aws ec2 describe-vpcs --region us-east-1 --profile default
```

## ⚙️ Configuration

### AWS Credentials Setup

```bash
# Configure default profile
aws configure --profile default

# Configure named profile
aws configure --profile mycompany

# View current configuration
aws configure list --profile default

# View all profiles
aws configure list-profiles
```

### Environment Variables (Alternative to --profile)

```bash
# Windows PowerShell
$env:AWS_PROFILE="default"
$env:AWS_DEFAULT_REGION="us-east-1"

# Windows CMD
set AWS_PROFILE=default
set AWS_DEFAULT_REGION=us-east-1

# Linux/Mac
export AWS_PROFILE=default
export AWS_DEFAULT_REGION=us-east-1
```

## 📊 Report Structure

```
reports/audit_TIMESTAMP/
├── audit_summary.json              # Overall compliance summary
├── iam_data.json                   # Raw IAM data collected
├── iam_compliance_report.json      # IAM findings (13 checks)
├── storage_data.json               # Raw Storage data
├── storage_compliance_report.json  # Storage findings (9 checks)
├── logging_data.json               # Raw Logging data
└── logging_compliance_report.json  # Logging findings (8 checks)
```

## 🎯 Common Scenarios

### Scenario 1: First Time Running

```bash
# 1. Verify setup
python test_setup.py

# 2. Test AWS credentials
aws sts get-caller-identity --profile default

# 3. Run IAM audit first (fastest)
python scripts/run_audit.py --category iam --profile default

# 4. Review results
python -m json.tool reports/audit_*/audit_summary.json
```

### Scenario 2: Profile Name Issues

```bash
# Check available profiles
aws configure list-profiles

# If 'default' not found, create it
aws configure --profile default

# Or use your specific profile name
python scripts/run_audit.py --category all --profile YOUR_PROFILE_NAME
```

### Scenario 3: Permission Issues

```bash
# Test permissions manually
aws iam list-users --profile default

# If AccessDenied:
# 1. Log into AWS Console
# 2. IAM → Users → Your user
# 3. Add permissions → Attach policies
# 4. Add: SecurityAudit + ViewOnlyAccess
```

### Scenario 4: Multi-Account Audit

```bash
# Configure each account as a profile
aws configure --profile account1
aws configure --profile account2
aws configure --profile account3

# Run audit for each
python scripts/run_audit.py --category all --profile account1
python scripts/run_audit.py --category all --profile account2
python scripts/run_audit.py --category all --profile account3

# Reports saved separately for each
```

## 🔍 Troubleshooting

```bash
# Check for typos in profile name
python scripts/run_audit.py --category all --profile defaul   # ❌ Wrong
python scripts/run_audit.py --category all --profile default  # ✅ Correct

# Debug AWS CLI issues
aws iam list-users --profile default --debug

# Check Python dependencies
pip list | grep -E "pandas|boto3|openpyxl"

# Re-install dependencies
pip install -r requirements.txt --upgrade
```

## 📈 Performance Tips

```bash
# Fast (single region, ~3-7 minutes)
python scripts/run_audit.py --category all --profile default

# Medium (specific category)
python scripts/run_audit.py --category iam --profile default

# Slow (all regions, ~10-20 minutes)
python scripts/run_audit.py --category all --profile default --all-regions
```

## 🔐 Required AWS Permissions

**Quick Setup:**
- Attach managed policy: `SecurityAudit`
- Attach managed policy: `ViewOnlyAccess`

**Minimal Custom Policy:**
See [AWS_PERMISSIONS_REQUIRED.md](AWS_PERMISSIONS_REQUIRED.md)

## 📚 Documentation Quick Links

| Document | Purpose |
|----------|---------|
| [QUICKSTART.md](QUICKSTART.md) | 5-minute setup |
| [TESTING_STEPS.txt](TESTING_STEPS.txt) | Step-by-step testing |
| [COMMON_ERRORS.md](COMMON_ERRORS.md) | Error troubleshooting |
| [AWS_PERMISSIONS_REQUIRED.md](AWS_PERMISSIONS_REQUIRED.md) | Permissions guide |
| [SECTIONS_OVERVIEW.md](SECTIONS_OVERVIEW.md) | All CIS sections |
| [USAGE.md](USAGE.md) | Complete usage guide |

## 🎯 Current Capabilities

| Section | Automated Checks | Status |
|---------|-----------------|--------|
| IAM | 13 | ✅ Working |
| Storage | 9 | ✅ Working |
| Logging | 8 | ✅ Working |
| Monitoring | 0 | ⚠️ Coming soon |
| Networking | 0 | ⚠️ Coming soon |
| **TOTAL** | **30** | **42% coverage** |

## 💡 Pro Tips

1. **Always use correct profile name** (check with `aws configure list-profiles`)
2. **Start with IAM audit first** (fastest, most important)
3. **Don't use --all-regions for testing** (too slow)
4. **Fix CRITICAL findings first**, then HIGH, MEDIUM, LOW
5. **Add SecurityAudit + ViewOnlyAccess policies** for easiest setup
6. **Run `python test_setup.py` first** to verify everything works

## ⚡ Quick Copy-Paste Commands

```bash
# Complete first-time setup and run
aws configure --profile default
python test_setup.py
python scripts/run_audit.py --category all --profile default
python -m json.tool reports/audit_*/audit_summary.json

# Quick re-run after fixes
python scripts/run_audit.py --category all --profile default

# View latest results
cd reports && ls -lt | head -5 && cd ..
python -m json.tool reports/audit_*/audit_summary.json
```

---

**Remember:** The most common issue is typos in the profile name!

**Your command had:** `--profile defaul` ❌
**Should be:** `--profile default` ✅
