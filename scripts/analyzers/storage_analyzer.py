#!/usr/bin/env python3
"""
Storage Compliance Analyzer for CIS AWS Benchmark (S3, RDS, EFS)
Analyzes collected storage data against CIS controls
"""

import json
from datetime import datetime
from typing import Dict, List, Any


class StorageAnalyzer:
    """Analyzes Storage data for CIS compliance"""

    def __init__(self, data_file: str):
        with open(data_file, 'r') as f:
            self.data = json.load(f)
        self.findings = []

    def add_finding(self, control: str, title: str, status: str, details: str, severity: str = "MEDIUM"):
        """Add a compliance finding"""
        self.findings.append({
            "control": control,
            "title": title,
            "status": status,  # PASS, FAIL, MANUAL
            "severity": severity,  # LOW, MEDIUM, HIGH, CRITICAL
            "details": details,
            "timestamp": datetime.now().isoformat()
        })

    # ===== S3 Controls =====

    def check_2_1_1_s3_https_enforcement(self):
        """CIS 2.1.1: Ensure S3 Bucket Policy is set to deny HTTP requests"""
        buckets = self.data.get("s3", {}).get("buckets", [])

        if not buckets:
            self.add_finding(
                "2.1.1",
                "No S3 buckets to check",
                "PASS",
                "No S3 buckets found in account",
                "LOW"
            )
            return

        buckets_without_https = []

        for bucket in buckets:
            bucket_name = bucket.get("name")
            policy = bucket.get("policy", {})

            # Check if policy enforces HTTPS
            has_https_enforcement = False

            if policy and isinstance(policy, dict):
                statements = policy.get("Statement", [])
                if isinstance(statements, list):
                    for statement in statements:
                        # Check for aws:SecureTransport condition
                        condition = statement.get("Condition", {})
                        effect = statement.get("Effect", "")

                        # Looking for: Effect: Deny with Condition: aws:SecureTransport: false
                        if effect == "Deny":
                            bool_cond = condition.get("Bool", {})
                            if bool_cond.get("aws:SecureTransport") == "false":
                                has_https_enforcement = True
                                break

            if not has_https_enforcement:
                buckets_without_https.append(bucket_name)

        if buckets_without_https:
            self.add_finding(
                "2.1.1",
                "S3 buckets without HTTPS enforcement",
                "FAIL",
                f"Buckets without HTTPS-only policy: {', '.join(buckets_without_https[:10])}",
                "HIGH"
            )
        else:
            self.add_finding(
                "2.1.1",
                "All S3 buckets enforce HTTPS",
                "PASS",
                f"All {len(buckets)} buckets enforce HTTPS"
            )

    def check_2_1_2_s3_mfa_delete(self):
        """CIS 2.1.2: Ensure MFA Delete is enabled on S3 buckets"""
        buckets = self.data.get("s3", {}).get("buckets", [])

        if not buckets:
            return

        buckets_without_mfa_delete = []

        for bucket in buckets:
            bucket_name = bucket.get("name")
            versioning = bucket.get("versioning", {})

            mfa_delete = versioning.get("MFADelete", "Disabled")
            versioning_status = versioning.get("Status", "")

            # MFA Delete requires versioning to be enabled
            if versioning_status != "Enabled" or mfa_delete != "Enabled":
                buckets_without_mfa_delete.append(bucket_name)

        if buckets_without_mfa_delete:
            self.add_finding(
                "2.1.2",
                "S3 buckets without MFA Delete",
                "FAIL",
                f"Buckets without MFA Delete: {', '.join(buckets_without_mfa_delete[:10])}",
                "MEDIUM"
            )
        else:
            self.add_finding(
                "2.1.2",
                "All S3 buckets have MFA Delete enabled",
                "PASS",
                f"All {len(buckets)} buckets have MFA Delete enabled"
            )

    def check_2_1_3_macie_enabled(self):
        """CIS 2.1.3: Ensure Macie is enabled for data discovery"""
        macie_status = self.data.get("s3", {}).get("macie_status", {})

        status = macie_status.get("status")

        if status == "ENABLED":
            self.add_finding(
                "2.1.3",
                "Macie is enabled",
                "PASS",
                "Amazon Macie is enabled for S3 data discovery"
            )
        else:
            self.add_finding(
                "2.1.3",
                "Macie not enabled",
                "FAIL",
                "Amazon Macie is not enabled for S3 data classification and discovery",
                "MEDIUM"
            )

    def check_2_1_4_s3_block_public_access(self):
        """CIS 2.1.4: Ensure Block Public Access is enabled on S3 buckets"""
        buckets = self.data.get("s3", {}).get("buckets", [])

        if not buckets:
            return

        buckets_without_block_public = []

        for bucket in buckets:
            bucket_name = bucket.get("name")
            public_access_block = bucket.get("public_access_block", {})

            # All four settings should be true
            block_public_acls = public_access_block.get("BlockPublicAcls", False)
            ignore_public_acls = public_access_block.get("IgnorePublicAcls", False)
            block_public_policy = public_access_block.get("BlockPublicPolicy", False)
            restrict_public_buckets = public_access_block.get("RestrictPublicBuckets", False)

            if not all([block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets]):
                buckets_without_block_public.append(bucket_name)

        if buckets_without_block_public:
            self.add_finding(
                "2.1.4",
                "S3 buckets without full Block Public Access",
                "FAIL",
                f"Buckets without Block Public Access: {', '.join(buckets_without_block_public[:10])}",
                "CRITICAL"
            )
        else:
            self.add_finding(
                "2.1.4",
                "All S3 buckets have Block Public Access enabled",
                "PASS",
                f"All {len(buckets)} buckets have Block Public Access enabled"
            )

    # ===== RDS Controls =====

    def check_2_2_1_rds_encryption(self):
        """CIS 2.2.1: Ensure RDS encryption at rest is enabled"""
        all_instances = []
        rds_data = self.data.get("rds", {})

        for region, data in rds_data.items():
            instances = data.get("instances", [])
            all_instances.extend([(region, inst) for inst in instances])

        if not all_instances:
            self.add_finding(
                "2.2.1",
                "No RDS instances to check",
                "PASS",
                "No RDS instances found in account",
                "LOW"
            )
            return

        unencrypted_instances = []

        for region, instance in all_instances:
            db_name = instance.get("DBInstanceIdentifier", "Unknown")
            encrypted = instance.get("StorageEncrypted", False)

            if not encrypted:
                unencrypted_instances.append(f"{db_name} ({region})")

        if unencrypted_instances:
            self.add_finding(
                "2.2.1",
                "RDS instances without encryption",
                "FAIL",
                f"Unencrypted instances: {', '.join(unencrypted_instances)}",
                "HIGH"
            )
        else:
            self.add_finding(
                "2.2.1",
                "All RDS instances are encrypted",
                "PASS",
                f"All {len(all_instances)} RDS instances have encryption at rest enabled"
            )

    def check_2_2_2_rds_auto_minor_upgrade(self):
        """CIS 2.2.2: Ensure RDS Auto Minor Version Upgrade is enabled"""
        all_instances = []
        rds_data = self.data.get("rds", {})

        for region, data in rds_data.items():
            instances = data.get("instances", [])
            all_instances.extend([(region, inst) for inst in instances])

        if not all_instances:
            return

        instances_without_auto_upgrade = []

        for region, instance in all_instances:
            db_name = instance.get("DBInstanceIdentifier", "Unknown")
            auto_upgrade = instance.get("AutoMinorVersionUpgrade", False)

            if not auto_upgrade:
                instances_without_auto_upgrade.append(f"{db_name} ({region})")

        if instances_without_auto_upgrade:
            self.add_finding(
                "2.2.2",
                "RDS instances without auto minor version upgrade",
                "FAIL",
                f"Instances without auto upgrade: {', '.join(instances_without_auto_upgrade)}",
                "MEDIUM"
            )
        else:
            self.add_finding(
                "2.2.2",
                "All RDS instances have auto minor version upgrade",
                "PASS",
                f"All {len(all_instances)} RDS instances have auto minor version upgrade enabled"
            )

    def check_2_2_3_rds_public_access(self):
        """CIS 2.2.3: Ensure RDS instances are not publicly accessible"""
        all_instances = []
        rds_data = self.data.get("rds", {})

        for region, data in rds_data.items():
            instances = data.get("instances", [])
            all_instances.extend([(region, inst) for inst in instances])

        if not all_instances:
            return

        public_instances = []

        for region, instance in all_instances:
            db_name = instance.get("DBInstanceIdentifier", "Unknown")
            publicly_accessible = instance.get("PubliclyAccessible", False)

            if publicly_accessible:
                public_instances.append(f"{db_name} ({region})")

        if public_instances:
            self.add_finding(
                "2.2.3",
                "Publicly accessible RDS instances found",
                "FAIL",
                f"Public instances: {', '.join(public_instances)}",
                "CRITICAL"
            )
        else:
            self.add_finding(
                "2.2.3",
                "No publicly accessible RDS instances",
                "PASS",
                f"All {len(all_instances)} RDS instances are not publicly accessible"
            )

    def check_2_2_4_rds_multi_az(self):
        """CIS 2.2.4: Ensure Multi-AZ is enabled for RDS instances"""
        all_instances = []
        rds_data = self.data.get("rds", {})

        for region, data in rds_data.items():
            instances = data.get("instances", [])
            all_instances.extend([(region, inst) for inst in instances])

        if not all_instances:
            return

        single_az_instances = []

        for region, instance in all_instances:
            db_name = instance.get("DBInstanceIdentifier", "Unknown")
            multi_az = instance.get("MultiAZ", False)

            if not multi_az:
                single_az_instances.append(f"{db_name} ({region})")

        if single_az_instances:
            self.add_finding(
                "2.2.4",
                "RDS instances without Multi-AZ",
                "FAIL",
                f"Single-AZ instances: {', '.join(single_az_instances)}",
                "HIGH"
            )
        else:
            self.add_finding(
                "2.2.4",
                "All RDS instances use Multi-AZ",
                "PASS",
                f"All {len(all_instances)} RDS instances have Multi-AZ enabled"
            )

    # ===== EFS Controls =====

    def check_2_3_1_efs_encryption(self):
        """CIS 2.3.1: Ensure EFS file systems are encrypted"""
        all_filesystems = []
        efs_data = self.data.get("efs", {})

        for region, data in efs_data.items():
            filesystems = data.get("filesystems", [])
            all_filesystems.extend([(region, fs) for fs in filesystems])

        if not all_filesystems:
            self.add_finding(
                "2.3.1",
                "No EFS file systems to check",
                "PASS",
                "No EFS file systems found in account",
                "LOW"
            )
            return

        unencrypted_filesystems = []

        for region, fs in all_filesystems:
            fs_id = fs.get("FileSystemId", "Unknown")
            encrypted = fs.get("Encrypted", False)

            if not encrypted:
                unencrypted_filesystems.append(f"{fs_id} ({region})")

        if unencrypted_filesystems:
            self.add_finding(
                "2.3.1",
                "Unencrypted EFS file systems found",
                "FAIL",
                f"Unencrypted file systems: {', '.join(unencrypted_filesystems)}",
                "HIGH"
            )
        else:
            self.add_finding(
                "2.3.1",
                "All EFS file systems are encrypted",
                "PASS",
                f"All {len(all_filesystems)} EFS file systems are encrypted"
            )

    def analyze_all(self):
        """Run all storage compliance checks"""
        print("="*60)
        print("Starting Storage compliance analysis...")
        print("="*60)

        # S3 checks
        self.check_2_1_1_s3_https_enforcement()
        self.check_2_1_2_s3_mfa_delete()
        self.check_2_1_3_macie_enabled()
        self.check_2_1_4_s3_block_public_access()

        # RDS checks
        self.check_2_2_1_rds_encryption()
        self.check_2_2_2_rds_auto_minor_upgrade()
        self.check_2_2_3_rds_public_access()
        self.check_2_2_4_rds_multi_az()

        # EFS checks
        self.check_2_3_1_efs_encryption()

        print(f"\nAnalysis complete! Total findings: {len(self.findings)}")

        # Summary
        passed = len([f for f in self.findings if f["status"] == "PASS"])
        failed = len([f for f in self.findings if f["status"] == "FAIL"])
        manual = len([f for f in self.findings if f["status"] == "MANUAL"])

        print(f"  PASS: {passed}")
        print(f"  FAIL: {failed}")
        print(f"  MANUAL: {manual}")

        return self.findings

    def save_report(self, filename: str):
        """Save analysis report to JSON file"""
        report = {
            "analysis_time": datetime.now().isoformat(),
            "summary": {
                "total_checks": len(self.findings),
                "passed": len([f for f in self.findings if f["status"] == "PASS"]),
                "failed": len([f for f in self.findings if f["status"] == "FAIL"]),
                "manual": len([f for f in self.findings if f["status"] == "MANUAL"])
            },
            "findings": self.findings
        }

        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"Report saved to: {filename}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Analyze Storage data for CIS compliance")
    parser.add_argument("--input", required=True, help="Input data file from Storage collector")
    parser.add_argument("--output", default="storage_compliance_report.json", help="Output report file")

    args = parser.parse_args()

    analyzer = StorageAnalyzer(args.input)
    analyzer.analyze_all()
    analyzer.save_report(args.output)
