# AWS Review - Testing Guide

This guide will walk you through testing the AWS security review automation tools.

## Prerequisites Check

### 1. Check Python Installation
```bash
python --version
```
**Expected:** Python 3.8 or higher (you have Python 3.13.3 ✅)

### 2. Install AWS CLI v2

**Check if installed:**
```bash
aws --version
```

**If not installed, download and install:**
- **Windows:** Download from https://awscli.amazonaws.com/AWSCLIV2.msi
- Or visit: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html

After installation, restart your terminal and verify:
```bash
aws --version
```

### 3. Install Python Dependencies
```bash
cd C:\Projects\AWS_Review
pip install -r requirements.txt
```

## AWS Account Setup

### Option A: Use Your Own AWS Account (Recommended for Testing)

1. **Configure AWS CLI with your credentials:**
   ```bash
   aws configure
   ```

   You'll be prompted for:
   - AWS Access Key ID: `AKIA...` (from AWS Console)
   - AWS Secret Access Key: `...` (from AWS Console)
   - Default region: `us-east-1` (or your preferred region)
   - Default output format: `json`

2. **Test AWS connectivity:**
   ```bash
   aws sts get-caller-identity
   ```

   **Expected output:**
   ```json
   {
       "UserId": "AIDA...",
       "Account": "123456789012",
       "Arn": "arn:aws:iam::123456789012:user/yourname"
   }
   ```

### Option B: Use AWS Test/Sandbox Account

If you have a test AWS account, use those credentials instead.

### Option C: Read-Only Testing (Safest)

Create an IAM user with **read-only** permissions for testing:

1. Go to AWS Console → IAM → Users → Add User
2. Create user with "Programmatic access"
3. Attach these managed policies:
   - `ReadOnlyAccess` (or use the custom policy below)
4. Save the Access Key ID and Secret Access Key
5. Use those credentials in `aws configure`

**Custom Read-Only Policy:**
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

## Testing Steps

### Test 1: Verify AWS CLI Configuration

```bash
# Check configuration
aws configure list

# Verify credentials work
aws sts get-caller-identity

# List IAM users (basic test)
aws iam list-users
```

**Expected:** Should return JSON with user list (or empty array if no users)

---

### Test 2: Run IAM Collector (Individual Component Test)

```bash
cd C:\Projects\AWS_Review

python scripts/collectors/iam_collector.py --profile default --output test_iam_data.json
```

**What it does:**
- Generates IAM credential report
- Collects password policies
- Lists all IAM users
- Checks MFA devices
- Analyzes policies
- Checks Access Analyzer status

**Expected output:**
```
============================================================
Starting IAM data collection...
============================================================
Generating IAM credential report...
Collecting IAM password policy...
Collecting IAM users...
Collecting data for user: alice
Collecting data for user: bob
...
IAM data collection complete!
Data saved to: test_iam_data.json
```

**Verify the output:**
```bash
# Check the file was created
ls -lh test_iam_data.json

# View first 50 lines
head -50 test_iam_data.json
```

---

### Test 3: Run IAM Analyzer

```bash
python scripts/analyzers/iam_analyzer.py --input test_iam_data.json --output test_iam_report.json
```

**What it does:**
- Analyzes collected data against 13 CIS controls
- Checks for security issues
- Generates compliance report

**Expected output:**
```
============================================================
Starting IAM compliance analysis...
============================================================

Analysis complete! Total findings: 13
  PASS: 10
  FAIL: 3
  MANUAL: 0
Report saved to: test_iam_report.json
```

**View the report:**
```bash
# Pretty print the report (Windows PowerShell)
Get-Content test_iam_report.json | ConvertFrom-Json | ConvertTo-Json -Depth 10

# Or with Python
python -m json.tool test_iam_report.json
```

---

### Test 4: Run Full IAM Audit (Collector + Analyzer)

```bash
python scripts/run_audit.py --category iam --profile default
```

**What it does:**
- Runs IAM collector
- Runs IAM analyzer
- Generates summary report
- Saves everything to `reports/audit_TIMESTAMP/`

**Expected output:**
```
================================================================================
CIS AWS FOUNDATIONS BENCHMARK v5.0.0 - AUTOMATED AUDIT
================================================================================
Audit started: 2024-01-14 14:30:00

AWS Profile: default
Primary Region: us-east-1
All Regions: False
Category: iam
Output Directory: reports/audit_20240114_143000

================================================================================
SECTION 1: IDENTITY AND ACCESS MANAGEMENT (IAM)
================================================================================
[... collection output ...]
[... analysis output ...]

================================================================================
AUDIT SUMMARY
================================================================================
Overall Compliance: 76.92%
Total Checks: 13

IAM:
  Compliance: 76.92%
  Passed: 10/13
  Failed: 3
  Manual: 0

Detailed reports saved to: reports/audit_20240114_143000
Summary report: reports/audit_20240114_143000/audit_summary.json

================================================================================
AUDIT COMPLETE
================================================================================
```

**View the reports:**
```bash
# List generated files
ls -lh reports/audit_*/

# View summary
python -m json.tool reports/audit_*/audit_summary.json

# View detailed findings
python -m json.tool reports/audit_*/iam_compliance_report.json
```

---

### Test 5: Storage Collector Test (Optional)

```bash
python scripts/collectors/storage_collector.py --profile default --output test_storage_data.json
```

**What it does:**
- Lists all S3 buckets
- Checks bucket policies
- Checks encryption settings
- Lists RDS instances
- Lists EFS file systems

**Note:** This will only work if you have S3 buckets or RDS instances in your account.

---

### Test 6: Logging Collector Test (Optional)

```bash
python scripts/collectors/logging_collector.py --profile default --output test_logging_data.json
```

**What it does:**
- Checks CloudTrail trails
- Checks AWS Config status
- Lists VPC Flow Logs
- Lists KMS keys
- Checks CloudWatch logs

---

### Test 7: Full Multi-Region Audit (Advanced)

⚠️ **Warning:** This can take 10-20 minutes and will scan all AWS regions.

```bash
python scripts/run_audit.py --category iam --profile default --all-regions
```

---

## Interpreting Results

### Understanding Findings

Each finding has:
- **control**: CIS control number (e.g., "1.3")
- **title**: Description of the check
- **status**: PASS, FAIL, or MANUAL
- **severity**: CRITICAL, HIGH, MEDIUM, LOW
- **details**: Specific information about the finding

### Example Findings:

**✅ PASS Example:**
```json
{
  "control": "1.7",
  "title": "Password policy meets minimum length",
  "status": "PASS",
  "severity": "MEDIUM",
  "details": "Minimum password length is 14"
}
```

**❌ FAIL Example:**
```json
{
  "control": "1.3",
  "title": "Root user has active access keys",
  "status": "FAIL",
  "severity": "CRITICAL",
  "details": "Root account has active access keys. Key1: true, Key2: false"
}
```

### Priority Actions:

1. **CRITICAL failures** - Fix immediately (e.g., root account security)
2. **HIGH failures** - Fix within days (e.g., missing MFA)
3. **MEDIUM failures** - Fix within weeks (e.g., old access keys)
4. **LOW failures** - Fix when convenient

---

## Troubleshooting

### Issue: "aws: command not found"
**Solution:**
1. Install AWS CLI v2 from https://aws.amazon.com/cli/
2. Restart your terminal
3. Verify with `aws --version`

### Issue: "ModuleNotFoundError: No module named 'pandas'"
**Solution:**
```bash
pip install -r requirements.txt
```

### Issue: "Unable to locate credentials"
**Solution:**
```bash
aws configure
# Enter your AWS Access Key ID and Secret Access Key
```

### Issue: "Access Denied" errors
**Solution:**
Your IAM user needs read permissions. Attach the `ReadOnlyAccess` policy or the custom policy from above.

### Issue: "No module named 'iam_collector'"
**Solution:**
Make sure you're running from the project root directory:
```bash
cd C:\Projects\AWS_Review
python scripts/collectors/iam_collector.py --profile default --output test.json
```

### Issue: Slow performance
**Solution:**
- Don't use `--all-regions` for initial testing
- Run specific categories (`--category iam`) instead of full audit
- Use a faster internet connection

---

## What to Expect in a Real AWS Account

### Typical Test Results:

**New/Clean Account:**
- Most checks will PASS
- Few or no IAM users
- May fail on root account security (if root keys exist)

**Development Account:**
- Some failures expected
- Common issues: old access keys, missing MFA, overly permissive policies

**Production Account:**
- Should have mostly PASS results
- Any CRITICAL/HIGH failures need immediate attention

---

## Next Steps After Testing

1. **Review the compliance report** - Check what passed/failed
2. **Prioritize fixes** - Start with CRITICAL and HIGH severity
3. **Implement remediations** - Follow AWS best practices
4. **Re-run audit** - Verify fixes worked
5. **Schedule regular audits** - Weekly or monthly

---

## Quick Test Checklist

- [ ] AWS CLI installed and configured
- [ ] Python 3.8+ installed
- [ ] Dependencies installed (`pip install -r requirements.txt`)
- [ ] AWS credentials configured (`aws configure`)
- [ ] Test AWS connectivity (`aws sts get-caller-identity`)
- [ ] Run IAM collector test
- [ ] Run IAM analyzer test
- [ ] Run full IAM audit
- [ ] Review generated reports
- [ ] (Optional) Test storage and logging collectors

---

## Safe Testing Tips

✅ **DO:**
- Use a test/sandbox AWS account
- Use read-only IAM credentials
- Start with single category (`--category iam`)
- Review reports in the `reports/` directory

❌ **DON'T:**
- Use production credentials on untrusted systems
- Grant write/delete permissions for testing
- Run in production without understanding the scripts
- Share AWS credentials or reports publicly

---

## Getting Help

If you encounter issues:
1. Check the error message carefully
2. Review the Troubleshooting section above
3. Verify AWS CLI works: `aws iam list-users`
4. Check Python environment: `python --version`
5. Ensure all dependencies installed: `pip install -r requirements.txt`

## Test Validation Checklist

After successful testing, you should have:
- [ ] `test_iam_data.json` - Raw IAM data
- [ ] `test_iam_report.json` - Compliance analysis
- [ ] `reports/audit_*/` - Full audit reports
- [ ] Compliance summary showing PASS/FAIL counts
- [ ] No Python errors or AWS access denied errors

---

**You're ready to test!** Start with Test 1 and work your way through the steps.
