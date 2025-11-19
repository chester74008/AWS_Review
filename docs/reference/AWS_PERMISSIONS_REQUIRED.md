# AWS Permissions Required for CIS Benchmark Audit

This document lists all AWS permissions required to run the complete CIS AWS Benchmark audit.

## Quick Setup - Use AWS Managed Policies

**Easiest Option:** Attach these AWS managed policies to your IAM user/role:

```json
{
  "PolicyArns": [
    "arn:aws:iam::aws:policy/SecurityAudit",
    "arn:aws:iam::aws:policy/ViewOnlyAccess"
  ]
}
```

These managed policies provide comprehensive read-only access for security auditing.

---

## Custom Minimal Permissions Policy

If you want to create a custom policy with only the minimum required permissions, use this:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CISAuditIAMPermissions",
      "Effect": "Allow",
      "Action": [
        "iam:GenerateCredentialReport",
        "iam:GetCredentialReport",
        "iam:GetAccountPasswordPolicy",
        "iam:GetAccountSummary",
        "iam:ListUsers",
        "iam:ListAccessKeys",
        "iam:ListMFADevices",
        "iam:ListAttachedUserPolicies",
        "iam:ListUserPolicies",
        "iam:ListPolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:ListEntitiesForPolicy",
        "iam:ListServerCertificates",
        "iam:GetServerCertificate"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CISAuditAccessAnalyzer",
      "Effect": "Allow",
      "Action": [
        "access-analyzer:ListAnalyzers",
        "access-analyzer:GetAnalyzer"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CISAuditS3Permissions",
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketPolicy",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketVersioning",
        "s3:GetBucketAcl",
        "s3:GetBucketLocation",
        "s3:GetBucketLogging",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetEncryptionConfiguration",
        "s3:GetAccountPublicAccessBlock"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CISAuditMaciePermissions",
      "Effect": "Allow",
      "Action": [
        "macie2:GetMacieSession",
        "macie2:ListClassificationJobs"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CISAuditRDSPermissions",
      "Effect": "Allow",
      "Action": [
        "rds:DescribeDBInstances",
        "rds:DescribeDBSnapshots",
        "rds:DescribeDBSnapshotAttributes",
        "rds:DescribeDBClusters",
        "rds:DescribeDBClusterSnapshots"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CISAuditEFSPermissions",
      "Effect": "Allow",
      "Action": [
        "elasticfilesystem:DescribeFileSystems",
        "elasticfilesystem:DescribeFileSystemPolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CISAuditCloudTrailPermissions",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:GetEventSelectors",
        "cloudtrail:GetTrail",
        "cloudtrail:ListTrails"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CISAuditConfigPermissions",
      "Effect": "Allow",
      "Action": [
        "config:DescribeConfigurationRecorders",
        "config:DescribeConfigurationRecorderStatus",
        "config:DescribeDeliveryChannels",
        "config:DescribeDeliveryChannelStatus"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CISAuditVPCPermissions",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeVpcs",
        "ec2:DescribeFlowLogs",
        "ec2:DescribeRegions",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeRouteTables",
        "ec2:DescribeInstances",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeSubnets"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CISAuditKMSPermissions",
      "Effect": "Allow",
      "Action": [
        "kms:ListKeys",
        "kms:ListAliases",
        "kms:DescribeKey",
        "kms:GetKeyRotationStatus",
        "kms:GetKeyPolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CISAuditCloudWatchPermissions",
      "Effect": "Allow",
      "Action": [
        "logs:DescribeLogGroups",
        "logs:DescribeMetricFilters",
        "cloudwatch:DescribeAlarms",
        "cloudwatch:DescribeAlarmsForMetric"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CISAuditSTSPermissions",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CISAuditAccountPermissions",
      "Effect": "Allow",
      "Action": [
        "account:GetAlternateContact"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Permissions Breakdown by Section

### Section 1: IAM Permissions

**Required for IAM audits (13 controls):**

```
iam:GenerateCredentialReport
iam:GetCredentialReport
iam:GetAccountPasswordPolicy
iam:GetAccountSummary
iam:ListUsers
iam:ListAccessKeys
iam:ListMFADevices
iam:ListAttachedUserPolicies
iam:ListUserPolicies
iam:ListPolicies
iam:GetPolicy
iam:GetPolicyVersion
iam:ListEntitiesForPolicy
iam:ListServerCertificates
iam:GetServerCertificate
access-analyzer:ListAnalyzers
access-analyzer:GetAnalyzer
account:GetAlternateContact
```

**What you can audit:**
- Root account security
- Password policies
- User MFA status
- Access key rotation
- Policy permissions
- SSL certificates
- Access Analyzer status

---

### Section 2: Storage Permissions

**S3 (4 controls):**

```
s3:ListAllMyBuckets
s3:GetBucketPolicy
s3:GetBucketVersioning
s3:GetBucketAcl
s3:GetBucketPublicAccessBlock
s3:GetEncryptionConfiguration
s3:GetAccountPublicAccessBlock
macie2:GetMacieSession
macie2:ListClassificationJobs
```

**RDS (4 controls):**

```
rds:DescribeDBInstances
rds:DescribeDBSnapshots
rds:DescribeDBSnapshotAttributes
rds:DescribeDBClusters
```

**EFS (1 control):**

```
elasticfilesystem:DescribeFileSystems
elasticfilesystem:DescribeFileSystemPolicy
```

**What you can audit:**
- S3 encryption and public access
- S3 bucket policies (HTTPS enforcement)
- S3 versioning and MFA Delete
- RDS encryption at rest
- RDS public accessibility
- EFS encryption

---

### Section 3 & 4: Logging and Monitoring Permissions

**CloudTrail (5 controls):**

```
cloudtrail:DescribeTrails
cloudtrail:GetTrailStatus
cloudtrail:GetEventSelectors
cloudtrail:GetTrail
cloudtrail:ListTrails
```

**AWS Config (1 control):**

```
config:DescribeConfigurationRecorders
config:DescribeConfigurationRecorderStatus
config:DescribeDeliveryChannels
```

**KMS (1 control):**

```
kms:ListKeys
kms:DescribeKey
kms:GetKeyRotationStatus
```

**VPC Flow Logs (1 control):**

```
ec2:DescribeVpcs
ec2:DescribeFlowLogs
```

**CloudWatch (15 controls):**

```
logs:DescribeLogGroups
logs:DescribeMetricFilters
cloudwatch:DescribeAlarms
```

**What you can audit:**
- CloudTrail multi-region configuration
- CloudTrail log validation
- AWS Config recorder status
- KMS key rotation
- VPC Flow Logs status
- CloudWatch metric filters and alarms

---

### Section 5: Networking Permissions

**VPC and Security Groups (9 controls):**

```
ec2:DescribeVpcs
ec2:DescribeSecurityGroups
ec2:DescribeNetworkAcls
ec2:DescribeRouteTables
ec2:DescribeInstances
ec2:DescribeNetworkInterfaces
ec2:DescribeSubnets
ec2:DescribeRegions
```

**What you can audit:**
- Default security group rules
- Security group configurations
- Network ACL rules
- VPC configurations
- EC2 instance public IPs

---

## How to Apply These Permissions

### Option 1: Create IAM User with Custom Policy (Recommended for Testing)

1. Log into AWS Console
2. Go to **IAM** → **Users** → **Add User**
3. Username: `aws-cis-auditor`
4. Access type: **Programmatic access**
5. Click **Next: Permissions**
6. Click **Attach policies directly**
7. Click **Create policy**
8. Copy the **Custom Minimal Permissions Policy** from above
9. Paste into the JSON editor
10. Name it: `CIS-AWS-Audit-Policy`
11. Click **Create policy**
12. Go back and attach the new policy to your user
13. **Save the Access Key ID and Secret Access Key**

### Option 2: Use AWS Managed Policies (Easiest)

1. Log into AWS Console
2. Go to **IAM** → **Users** → Select your user
3. Click **Add permissions** → **Attach policies directly**
4. Search for and attach:
   - `SecurityAudit`
   - `ViewOnlyAccess`
5. Click **Add permissions**

### Option 3: Assume Role (For Production)

If auditing multiple accounts:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::AUDITOR-ACCOUNT-ID:user/auditor"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

Attach the custom permissions policy to this role.

---

## Testing Your Permissions

After setting up permissions, test with:

```bash
# Test IAM permissions
aws iam generate-credential-report
aws iam list-users

# Test S3 permissions
aws s3api list-buckets

# Test CloudTrail permissions
aws cloudtrail describe-trails

# Test RDS permissions
aws rds describe-db-instances --region us-east-1

# Run setup test
python test_setup.py
```

---

## Common Permission Errors and Fixes

### Error: "AccessDenied" on IAM operations

**Fix:** Add `iam:GenerateCredentialReport` and `iam:GetCredentialReport` permissions

### Error: "AccessDenied" on S3 operations

**Fix:** Add `s3:ListAllMyBuckets` and `s3:GetBucket*` permissions

### Error: "AccessDenied" on CloudTrail

**Fix:** Add `cloudtrail:Describe*` and `cloudtrail:Get*` permissions

### Error: "AccessDenied" on Config

**Fix:** Add `config:Describe*` permissions

### Error: "AccessDenied" on Macie

**Fix:** Add `macie2:GetMacieSession` permission
Note: Macie must be enabled in the region first

### Error: "AccessDenied" on Access Analyzer

**Fix:** Add `access-analyzer:ListAnalyzers` permission

---

## Permissions by Analysis Level

### Minimum (IAM Only):
- Use IAM permissions section only
- ~13 controls automated

### Standard (IAM + Storage + Logging):
- Use IAM, S3, RDS, EFS, CloudTrail, Config, KMS, VPC permissions
- ~30 controls automated

### Complete (All Sections):
- Use full custom policy above
- ~50+ controls automated

---

## Security Best Practices

1. **Use Read-Only Permissions**: These policies grant only read access
2. **Principle of Least Privilege**: Only grant permissions for sections you need
3. **Use IAM Roles**: Prefer IAM roles over access keys when possible
4. **Rotate Credentials**: Regularly rotate access keys
5. **Enable MFA**: Require MFA for the auditor IAM user
6. **Audit the Auditor**: Monitor the auditor account's activity

---

## Multi-Account Setup

For auditing multiple AWS accounts:

1. **Create auditor account** (central account)
2. **Create cross-account role** in each target account
3. **Trust policy** allows auditor account to assume role
4. **Attach** CIS Audit Policy to the role
5. **Use** `aws sts assume-role` to switch accounts

Example assume-role command:

```bash
aws sts assume-role \
  --role-arn "arn:aws:iam::TARGET-ACCOUNT-ID:role/CISAuditorRole" \
  --role-session-name "CISAudit"
```

---

## Verifying Permissions Are Working

Run this to verify all permissions:

```bash
# Verify you can run audit
python scripts/run_audit.py --category all --profile default

# Check for AccessDenied errors
# If you see errors, check which API calls failed and add those permissions
```

---

## Summary

| Setup Method | Permissions | Difficulty | Use Case |
|--------------|-------------|------------|----------|
| **AWS Managed Policies** | SecurityAudit + ViewOnlyAccess | Easy | Testing, small environments |
| **Custom Minimal Policy** | Only required permissions | Medium | Production, compliance |
| **Cross-Account Role** | Minimal + assume role | Hard | Multi-account auditing |

**Recommendation:** Start with AWS managed policies for testing, then move to custom policy for production use.
