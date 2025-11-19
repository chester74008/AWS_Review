# Common Errors and Quick Fixes

## Error: "The config profile (defaul) could not be found"

### Cause
Typo in profile name or profile doesn't exist.

### Fix

**Check your typo:**
```bash
# Wrong ❌
python scripts/run_audit.py --category all --profile defaul

# Correct ✅
python scripts/run_audit.py --category all --profile default
```

**List available profiles:**
```bash
aws configure list-profiles
```

**Common profile names:**
- `default` (most common)
- `dev`
- `prod`
- `testing`

**If profile doesn't exist, create it:**
```bash
aws configure --profile default
# Then enter your AWS credentials
```

---

## Error: "AccessDenied" or "UnauthorizedOperation"

### Cause
Your IAM user/role lacks required permissions.

### Fix

**Quick Fix - Add AWS Managed Policies:**

1. Log into AWS Console
2. Go to: **IAM** → **Users** → Select your user
3. Click **Add permissions** → **Attach policies directly**
4. Add these policies:
   - `SecurityAudit`
   - `ViewOnlyAccess`
5. Click **Add permissions**

**Verify permissions:**
```bash
aws iam list-users --profile default
aws s3api list-buckets --profile default
```

If these work, you have correct permissions.

---

## Error: "No module named 'pandas'"

### Cause
Python dependencies not installed.

### Fix
```bash
pip install -r requirements.txt
```

---

## Error: "aws: command not found"

### Cause
AWS CLI not installed or not in PATH.

### Fix

**Install AWS CLI v2:**
- Windows: https://awscli.amazonaws.com/AWSCLIV2.msi
- After install, restart your terminal

**Verify:**
```bash
aws --version
```

---

## Error: Empty or No Data Collected

### Symptoms
```json
{
  "s3": {
    "buckets": []
  },
  "rds": {
    "us-east-1": {
      "instances": []
    }
  }
}
```

### Causes
1. **Wrong profile name** (like your case)
2. **No resources in account** (new/empty AWS account)
3. **Wrong region** (resources in different region)

### Fix

**1. Check profile name:**
```bash
# List profiles
aws configure list-profiles

# Use correct profile
python scripts/run_audit.py --category all --profile YOUR_PROFILE_NAME
```

**2. Check if you have resources:**
```bash
aws s3 ls --profile default
aws rds describe-db-instances --region us-east-1 --profile default
aws iam list-users --profile default
```

**3. Try different region:**
```bash
python scripts/run_audit.py --category all --profile default --region us-west-2
```

---

## Error: "Unable to locate credentials"

### Cause
AWS credentials not configured.

### Fix
```bash
aws configure --profile default

# Enter when prompted:
# AWS Access Key ID: AKIA...
# AWS Secret Access Key: ...
# Default region name: us-east-1
# Default output format: json
```

**Get credentials from AWS Console:**
1. IAM → Users → Your username
2. Security credentials tab
3. Create access key
4. Save the keys

---

## Analysis Shows Unexpected Results

### Example Issues

**IAM shows PASS but you know you have issues:**
- Probably no data collected (check for AWS CLI errors)
- Empty credential report = no users to check = PASS

**Storage shows PASS but you have S3 buckets:**
- Wrong profile or region
- AccessDenied on S3 operations
- Check if buckets list is empty in storage_data.json

**All checks PASS with 0 resources:**
- Data collection failed (check errors)
- Empty AWS account
- Wrong profile/region

### Fix

**1. Check for errors in output:**
Look for lines like:
```
Error running command: The config profile (defaul) could not be found
Error running command: AccessDenied
```

**2. Verify data was collected:**
```bash
# Check data files have content
python -c "import json; print(json.load(open('reports/audit_*/iam_data.json'))['users'][:3])"
```

**3. Run with verbose AWS CLI:**
```bash
# Test individual AWS commands
aws iam list-users --profile default --debug
```

---

## Performance Issues / Timeout

### Symptoms
Script hangs or times out.

### Fix

**1. Don't use --all-regions for testing:**
```bash
# Fast (single region)
python scripts/run_audit.py --category all --profile default

# Slow (all regions)
python scripts/run_audit.py --category all --profile default --all-regions
```

**2. Run specific category:**
```bash
python scripts/run_audit.py --category iam --profile default
```

**3. Check network connection:**
```bash
aws sts get-caller-identity --profile default
```

---

## Quick Diagnostics Checklist

Run these commands to diagnose issues:

```bash
# 1. Check AWS CLI installed
aws --version

# 2. Check Python version
python --version

# 3. Check available profiles
aws configure list-profiles

# 4. Check current profile config
aws configure list --profile default

# 5. Test AWS connectivity
aws sts get-caller-identity --profile default

# 6. Test IAM permissions
aws iam list-users --profile default

# 7. Test S3 permissions
aws s3 ls --profile default

# 8. Run setup verification
python test_setup.py
```

---

## Still Having Issues?

### Debug Mode

**1. Enable AWS CLI debug output:**
```bash
export AWS_DEBUG=1  # Linux/Mac
set AWS_DEBUG=1     # Windows CMD
$env:AWS_DEBUG=1    # Windows PowerShell

python scripts/run_audit.py --category iam --profile default
```

**2. Check data files:**
```bash
# View collected data
python -m json.tool reports/audit_*/iam_data.json
python -m json.tool reports/audit_*/storage_data.json
python -m json.tool reports/audit_*/logging_data.json
```

**3. Test individual collector:**
```bash
python scripts/collectors/iam_collector.py --profile default --output test.json
cat test.json
```

---

## Your Specific Error

**What you ran:**
```bash
python scripts/run_audit.py --category all --profile defaul  # ❌ Missing 't'
```

**Error:**
```
The config profile (defaul) could not be found
```

**Fix:**
```bash
python scripts/run_audit.py --category all --profile default  # ✅ Correct
```

**Verify your profile name:**
```bash
aws configure list-profiles

# Output should include 'default'
```

**If 'default' doesn't exist, create it:**
```bash
aws configure --profile default
# Enter your AWS credentials
```

---

## Summary of Common Fixes

| Error | Quick Fix |
|-------|-----------|
| **Wrong profile name** | Use `--profile default` (check typos!) |
| **Profile not found** | Run `aws configure --profile default` |
| **AccessDenied** | Add SecurityAudit + ViewOnlyAccess policies |
| **No credentials** | Run `aws configure` |
| **AWS CLI not found** | Install AWS CLI v2 |
| **No data collected** | Fix profile name and permissions |
| **Slow performance** | Don't use `--all-regions` |

---

**Most Common Issue:** Typo in profile name or missing AWS credentials

**Quick Test:**
```bash
aws sts get-caller-identity --profile default
```

If this works, your profile and credentials are correct!
