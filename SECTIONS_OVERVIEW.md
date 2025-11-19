# CIS AWS Benchmark - Sections Overview

## All Sections in the Benchmark (72 controls total)

Based on **CIS Amazon Web Services Foundations Benchmark v5.0.0**, here are all the sections:

### 📊 Section Breakdown

| Section | Category | Controls | Collector Status | Analyzer Status |
|---------|----------|----------|------------------|-----------------|
| **1.0** | **Identity and Access Management (IAM)** | 21 | ✅ Built | ✅ Built (13 checks) |
| **2.1** | **Storage - S3** | 4 | ✅ Built | ⚠️ Pending |
| **2.2** | **Storage - RDS** | 4 | ✅ Built | ⚠️ Pending |
| **2.3** | **Storage - EFS** | 1 | ✅ Built | ⚠️ Pending |
| **3.0** | **Logging - CloudTrail & Config** | 9 | ✅ Built | ⚠️ Pending |
| **4.0** | **Monitoring - CloudWatch** | 15 | ✅ Built | ⚠️ Pending |
| **5.0** | **Networking - VPC** | 5 | ⚠️ Partial | ⚠️ Pending |
| **5.1** | **Networking - Security Groups** | 4 | ⚠️ Partial | ⚠️ Pending |

**Total: 63+ controls across 8 sections**

---

## Detailed Section Information

### Section 1.0: Identity and Access Management (IAM)
**21 controls** covering:
- Root account security (access keys, MFA, hardware MFA)
- Contact information
- IAM user credentials management
- Password policies
- MFA enforcement
- Access key rotation
- Group-based permissions
- Policy restrictions
- Support roles
- IAM Access Analyzer
- CloudShell access restrictions

**Status:** ✅ **Fully Functional**
- Collector: `scripts/collectors/iam_collector.py`
- Analyzer: `scripts/analyzers/iam_analyzer.py` (13 automated checks)

---

### Section 2.1: Storage - S3 Buckets
**4 controls** covering:
- 2.1.1: S3 HTTPS enforcement (bucket policies)
- 2.1.2: S3 MFA Delete configuration
- 2.1.3: Macie for data discovery and classification
- 2.1.4: S3 Block Public Access settings

**Status:** ✅ Data Collection Working | ⚠️ Analysis Pending
- Collector: `scripts/collectors/storage_collector.py`
- Analyzer: Not yet implemented

---

### Section 2.2: Storage - RDS Databases
**4 controls** covering:
- 2.2.1: RDS encryption at rest
- 2.2.2: RDS auto minor version upgrade
- 2.2.3: RDS public accessibility
- 2.2.4: RDS Multi-AZ deployments

**Status:** ✅ Data Collection Working | ⚠️ Analysis Pending
- Collector: `scripts/collectors/storage_collector.py`
- Analyzer: Not yet implemented

---

### Section 2.3: Storage - EFS File Systems
**1 control** covering:
- 2.3.1: EFS encryption at rest

**Status:** ✅ Data Collection Working | ⚠️ Analysis Pending
- Collector: `scripts/collectors/storage_collector.py`
- Analyzer: Not yet implemented

---

### Section 3.0: Logging - CloudTrail & AWS Config
**9 controls** covering:
- 3.1: CloudTrail enabled in all regions
- 3.2: CloudTrail log file validation
- 3.3: AWS Config enabled in all regions
- 3.4: S3 bucket logging for CloudTrail
- 3.5: CloudTrail KMS encryption
- 3.6: KMS key rotation
- 3.7: VPC Flow Logs enabled
- 3.8: S3 object-level logging (write events)
- 3.9: S3 object-level logging (read events)

**Status:** ✅ Data Collection Working | ⚠️ Analysis Pending
- Collector: `scripts/collectors/logging_collector.py`
- Analyzer: Not yet implemented

---

### Section 4.0: Monitoring - CloudWatch Metric Filters & Alarms
**15 controls** covering:
- 4.1: Monitoring for unauthorized API calls
- 4.2: Monitoring for Console sign-in without MFA
- 4.3: Monitoring for root account usage
- 4.4: Monitoring for IAM policy changes
- 4.5: Monitoring for CloudTrail config changes
- 4.6: Monitoring for failed console authentication
- 4.7: Monitoring for KMS key deletion/disabling
- 4.8: Monitoring for S3 bucket policy changes
- 4.9: Monitoring for AWS Config changes
- 4.10: Monitoring for security group changes
- 4.11: Monitoring for NACL changes
- 4.12: Monitoring for network gateway changes
- 4.13: Monitoring for route table changes
- 4.14: Monitoring for VPC changes
- 4.15: Monitoring for Organizations changes

**Status:** ✅ Data Collection Working | ⚠️ Analysis Pending
- Collector: `scripts/collectors/logging_collector.py` (CloudWatch data)
- Analyzer: Not yet implemented

---

### Section 5.0 & 5.1: Networking - VPC & Security Groups
**9 controls** covering:
- 5.1: Default security group restrictions
- 5.2: Network ACL inbound/outbound rules
- 5.3: Security group port restrictions
- 5.4: EC2 instance public IP addresses
- And more networking security controls

**Status:** ⚠️ Partial Collection | ⚠️ Analysis Pending
- Collector: Partially in `logging_collector.py` (VPC data)
- Dedicated networking collector needed
- Analyzer: Not yet implemented

---

## Testing All Sections at Once

### Command to Test Everything:

```bash
python scripts/run_audit.py --category all --profile default
```

### What This Does:

1. **Runs IAM Section**
   - ✅ Collects all IAM data
   - ✅ Analyzes 13 IAM controls
   - ✅ Generates compliance report

2. **Runs Storage Section**
   - ✅ Collects S3 bucket data (policies, encryption, public access)
   - ✅ Collects RDS instance data (encryption, accessibility)
   - ✅ Collects EFS file system data (encryption)
   - ⚠️ Shows "analysis not yet implemented" message

3. **Runs Logging Section**
   - ✅ Collects CloudTrail trail configurations
   - ✅ Collects AWS Config status
   - ✅ Collects VPC Flow Logs
   - ✅ Collects KMS key rotation status
   - ✅ Collects CloudWatch Log Groups and Metric Filters
   - ⚠️ Shows "analysis not yet implemented" message

### Sample Output:

```
================================================================================
CIS AWS FOUNDATIONS BENCHMARK v5.0.0 - AUTOMATED AUDIT
================================================================================
Audit started: 2024-01-14 14:30:00

AWS Profile: default
Primary Region: us-east-1
All Regions: False
Category: all
Output Directory: reports/audit_20240114_143000

================================================================================
SECTION 1: IDENTITY AND ACCESS MANAGEMENT (IAM)
================================================================================
Starting IAM data collection...
Generating IAM credential report...
Collecting IAM users...
...
IAM data collection complete!

Starting IAM compliance analysis...
...
Analysis complete! Total findings: 13
  PASS: 10
  FAIL: 3
  MANUAL: 0

================================================================================
SECTION 2: STORAGE (S3, RDS, EFS)
================================================================================
Starting Storage data collection...
Collecting S3 buckets...
Collecting data for S3 bucket: my-bucket-1
Collecting data for S3 bucket: my-bucket-2
...
Collecting RDS instances in us-east-1...
Collecting EFS file systems in us-east-1...
Storage data collection complete!

Note: Storage compliance analysis not yet implemented

================================================================================
SECTION 3 & 4: LOGGING AND MONITORING
================================================================================
Starting Logging & Monitoring data collection...
Collecting CloudTrail trails in us-east-1...
Collecting AWS Config recorders in us-east-1...
Collecting VPCs in us-east-1...
Collecting KMS keys in us-east-1...
Collecting CloudWatch Log Groups in us-east-1...
Collecting CloudWatch Alarms in us-east-1...
...
Logging & Monitoring data collection complete!

Note: Logging compliance analysis not yet implemented

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

Storage:
  Total: 0
  (Analysis pending)

Logging:
  Total: 0
  (Analysis pending)

Detailed reports saved to: reports/audit_20240114_143000
Summary report: reports/audit_20240114_143000/audit_summary.json

================================================================================
AUDIT COMPLETE
================================================================================
```

---

## Generated Files

After running `--category all`, you'll find these files in `reports/audit_TIMESTAMP/`:

```
reports/audit_20240114_143000/
├── audit_summary.json           # Overall summary
├── iam_data.json                # Raw IAM data collected
├── iam_compliance_report.json   # IAM compliance findings
├── storage_data.json            # Raw storage data (S3, RDS, EFS)
└── logging_data.json            # Raw logging data (CloudTrail, Config, VPC, KMS, CloudWatch)
```

---

## What Works Now vs. What's Coming

### ✅ Fully Working (Test Now!)

**IAM Section (1.0):**
```bash
python scripts/run_audit.py --category iam --profile default
```
- Full data collection
- 13 automated compliance checks
- PASS/FAIL findings with severity
- Actionable recommendations

### ✅ Data Collection Working (No Analysis Yet)

**Storage & Logging Sections (2.x, 3.x, 4.x):**
```bash
python scripts/run_audit.py --category all --profile default
```
- All data collected successfully
- Saved to JSON files for manual review
- Ready for you to build analyzers

### ⚠️ To Be Implemented

**Networking Section (5.x):**
- Needs dedicated collector
- Needs analyzer

---

## Individual Section Testing

You can also test sections individually:

```bash
# IAM only (with analysis)
python scripts/run_audit.py --category iam --profile default

# Storage only (data collection)
python scripts/collectors/storage_collector.py --profile default --output storage.json

# Logging only (data collection)
python scripts/collectors/logging_collector.py --profile default --output logging.json
```

---

## Multi-Region Testing

To scan across ALL AWS regions (takes 10-20 minutes):

```bash
python scripts/run_audit.py --category all --profile default --all-regions
```

This will:
- Scan IAM (global service) once
- Scan S3, RDS, EFS in all regions
- Scan CloudTrail, Config, VPC Flow Logs in all regions
- Collect CloudWatch data from all regions

---

## Next Steps to Extend the Project

To add analysis for Storage and Logging sections:

1. **Create Storage Analyzer:**
   - Copy `scripts/analyzers/iam_analyzer.py`
   - Rename to `storage_analyzer.py`
   - Implement checks for S3, RDS, EFS controls
   - Add to `run_audit.py`

2. **Create Logging Analyzer:**
   - Copy `scripts/analyzers/iam_analyzer.py`
   - Rename to `logging_analyzer.py`
   - Implement checks for CloudTrail, Config, VPC controls
   - Add to `run_audit.py`

3. **Create Networking Collector & Analyzer:**
   - Build collector for VPC, Security Groups, NACLs
   - Build analyzer for Section 5.x controls

---

## Quick Reference

| Command | What It Does |
|---------|--------------|
| `python test_setup.py` | Verify your environment is ready |
| `python scripts/run_audit.py --category iam --profile default` | Test IAM (full analysis) |
| `python scripts/run_audit.py --category all --profile default` | Test all sections |
| `python scripts/run_audit.py --category all --profile default --all-regions` | Comprehensive multi-region audit |

---

**Bottom Line:** You can test **all sections** right now with `--category all`, but only the **IAM section** will provide compliance analysis. The other sections will collect all the data successfully and save it for you to analyze.
