# Quick Start - 5 Minutes to Your First Audit

## Step 1: Install AWS CLI (if not already installed)

Download and install from: https://awscli.amazonaws.com/AWSCLIV2.msi

After installation, restart your terminal and verify:
```bash
aws --version
```

## Step 2: Install Python Dependencies

```bash
cd C:\Projects\AWS_Review
pip install -r requirements.txt
```

## Step 3: Configure AWS Credentials

```bash
aws configure
```

Enter when prompted:
- **AWS Access Key ID**: Get from AWS Console → IAM → Users → Security Credentials
- **AWS Secret Access Key**: Get from same location
- **Default region**: `us-east-1` (or your preferred region)
- **Output format**: `json`

## Step 4: Test Your Setup

```bash
python test_setup.py
```

This will check:
- ✓ Python version
- ✓ AWS CLI installation
- ✓ AWS credentials
- ✓ Required packages
- ✓ Project files
- ✓ AWS permissions

## Step 5: Run Your First Audit

### Option A: Test Individual Collector
```bash
python scripts/collectors/iam_collector.py --profile default --output test_iam.json
```

### Option B: Run Full IAM Audit (Recommended)
```bash
python scripts/run_audit.py --category iam --profile default
```

## View Results

Results are saved in: `reports/audit_TIMESTAMP/`

```bash
# View summary
python -m json.tool reports/audit_*/audit_summary.json

# View detailed findings
python -m json.tool reports/audit_*/iam_compliance_report.json
```

## What's Next?

- Read [TESTING_GUIDE.md](TESTING_GUIDE.md) for detailed testing steps
- Read [USAGE.md](USAGE.md) for all available options
- Read [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md) for complete documentation

## Troubleshooting

**Problem:** `aws: command not found`
**Solution:** Install AWS CLI from link above, restart terminal

**Problem:** `Unable to locate credentials`
**Solution:** Run `aws configure` and enter your credentials

**Problem:** `AccessDenied` errors
**Solution:** Your IAM user needs read permissions (attach ReadOnlyAccess policy)

**Problem:** `ModuleNotFoundError`
**Solution:** Run `pip install -r requirements.txt`

## Need Help?

1. Run the setup verification: `python test_setup.py`
2. Check [TESTING_GUIDE.md](TESTING_GUIDE.md)
3. Review error messages carefully - they usually indicate what's missing

---

**Ready to audit!** 🚀
