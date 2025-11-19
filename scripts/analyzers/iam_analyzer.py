#!/usr/bin/env python3
"""
IAM Compliance Analyzer for CIS AWS Benchmark
Analyzes collected IAM data against CIS controls
"""

import json
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any


class IAMAnalyzer:
    """Analyzes IAM data for CIS compliance"""

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

    def check_1_3_root_access_keys(self):
        """CIS 1.3: Ensure no 'root' user account access key exists"""
        credentials = self.data.get("credential_report", {}).get("credentials", [])

        for cred in credentials:
            if cred.get("user") == "<root_account>":
                key1_active = cred.get("access_key_1_active") == "true"
                key2_active = cred.get("access_key_2_active") == "true"

                if key1_active or key2_active:
                    self.add_finding(
                        "1.3",
                        "Root user has active access keys",
                        "FAIL",
                        f"Root account has active access keys. Key1: {key1_active}, Key2: {key2_active}",
                        "CRITICAL"
                    )
                else:
                    self.add_finding(
                        "1.3",
                        "No root user access keys",
                        "PASS",
                        "Root account does not have active access keys"
                    )
                return

    def check_1_4_root_mfa(self):
        """CIS 1.4: Ensure MFA is enabled for the 'root' user account"""
        credentials = self.data.get("credential_report", {}).get("credentials", [])

        for cred in credentials:
            if cred.get("user") == "<root_account>":
                mfa_active = cred.get("mfa_active") == "true"
                password_enabled = cred.get("password_enabled") == "true"

                if password_enabled and not mfa_active:
                    self.add_finding(
                        "1.4",
                        "Root user MFA not enabled",
                        "FAIL",
                        "Root account has password enabled but no MFA configured",
                        "CRITICAL"
                    )
                else:
                    self.add_finding(
                        "1.4",
                        "Root user MFA enabled",
                        "PASS",
                        f"Root account MFA status: {mfa_active}"
                    )
                return

    def check_1_7_password_length(self):
        """CIS 1.7: Ensure IAM password policy requires minimum length of 14 or greater"""
        policy = self.data.get("password_policy", {}).get("PasswordPolicy", {})
        min_length = policy.get("MinimumPasswordLength", 0)

        if min_length >= 14:
            self.add_finding(
                "1.7",
                "Password policy meets minimum length",
                "PASS",
                f"Minimum password length is {min_length}"
            )
        else:
            self.add_finding(
                "1.7",
                "Password policy does not meet minimum length",
                "FAIL",
                f"Minimum password length is {min_length}, should be 14 or greater",
                "HIGH"
            )

    def check_1_8_password_reuse(self):
        """CIS 1.8: Ensure IAM password policy prevents password reuse"""
        policy = self.data.get("password_policy", {}).get("PasswordPolicy", {})
        reuse_prevention = policy.get("PasswordReusePrevention", 0)

        if reuse_prevention >= 24:
            self.add_finding(
                "1.8",
                "Password reuse prevention configured",
                "PASS",
                f"Password reuse prevention set to {reuse_prevention} passwords"
            )
        else:
            self.add_finding(
                "1.8",
                "Password reuse prevention not configured properly",
                "FAIL",
                f"Password reuse prevention is {reuse_prevention}, should be 24 or greater",
                "MEDIUM"
            )

    def check_1_9_user_mfa(self):
        """CIS 1.9: Ensure MFA is enabled for all IAM users with console password"""
        users_without_mfa = []

        for user_data in self.data.get("users", []):
            username = user_data.get("user_info", {}).get("UserName")
            mfa_devices = user_data.get("mfa_devices", [])

            # Check if user has console access (from credential report)
            credentials = self.data.get("credential_report", {}).get("credentials", [])
            for cred in credentials:
                if cred.get("user") == username:
                    password_enabled = cred.get("password_enabled") == "true"

                    if password_enabled and len(mfa_devices) == 0:
                        users_without_mfa.append(username)

        if users_without_mfa:
            self.add_finding(
                "1.9",
                "Users with console access lack MFA",
                "FAIL",
                f"Users without MFA: {', '.join(users_without_mfa)}",
                "HIGH"
            )
        else:
            self.add_finding(
                "1.9",
                "All console users have MFA enabled",
                "PASS",
                "All IAM users with console passwords have MFA enabled"
            )

    def check_1_11_unused_credentials(self):
        """CIS 1.11: Ensure credentials unused for 45 days or more are disabled"""
        unused_credentials = []
        cutoff_date = datetime.now() - timedelta(days=45)

        credentials = self.data.get("credential_report", {}).get("credentials", [])

        for cred in credentials:
            username = cred.get("user")
            if username == "<root_account>":
                continue

            # Check console last used
            password_enabled = cred.get("password_enabled") == "true"
            password_last_used = cred.get("password_last_used")

            if password_enabled and password_last_used != "N/A" and password_last_used != "no_information":
                try:
                    last_used = datetime.fromisoformat(password_last_used.replace("Z", "+00:00"))
                    if last_used < cutoff_date:
                        unused_credentials.append(f"{username} (console)")
                except:
                    pass

            # Check access keys
            for key_num in [1, 2]:
                key_active = cred.get(f"access_key_{key_num}_active") == "true"
                key_last_used = cred.get(f"access_key_{key_num}_last_used_date")

                if key_active and key_last_used and key_last_used != "N/A":
                    try:
                        last_used = datetime.fromisoformat(key_last_used.replace("Z", "+00:00"))
                        if last_used < cutoff_date:
                            unused_credentials.append(f"{username} (access_key_{key_num})")
                    except:
                        pass

        if unused_credentials:
            self.add_finding(
                "1.11",
                "Unused credentials detected",
                "FAIL",
                f"Credentials unused for 45+ days: {', '.join(unused_credentials)}",
                "MEDIUM"
            )
        else:
            self.add_finding(
                "1.11",
                "No unused credentials",
                "PASS",
                "All credentials have been used within 45 days"
            )

    def check_1_12_single_access_key(self):
        """CIS 1.12: Ensure there is only one active access key for any single IAM user"""
        users_with_multiple_keys = []

        for user_data in self.data.get("users", []):
            username = user_data.get("user_info", {}).get("UserName")
            access_keys = user_data.get("access_keys", [])

            active_keys = [key for key in access_keys if key.get("Status") == "Active"]

            if len(active_keys) > 1:
                users_with_multiple_keys.append(f"{username} ({len(active_keys)} keys)")

        if users_with_multiple_keys:
            self.add_finding(
                "1.12",
                "Users with multiple active access keys",
                "FAIL",
                f"Users with multiple keys: {', '.join(users_with_multiple_keys)}",
                "MEDIUM"
            )
        else:
            self.add_finding(
                "1.12",
                "All users have single access key",
                "PASS",
                "No users have more than one active access key"
            )

    def check_1_13_access_key_rotation(self):
        """CIS 1.13: Ensure access keys are rotated every 90 days or less"""
        old_keys = []
        cutoff_date = datetime.now() - timedelta(days=90)

        for user_data in self.data.get("users", []):
            username = user_data.get("user_info", {}).get("UserName")
            access_keys = user_data.get("access_keys", [])

            for key in access_keys:
                if key.get("Status") == "Active":
                    created_date_str = key.get("CreateDate")
                    if created_date_str:
                        try:
                            created_date = datetime.fromisoformat(created_date_str.replace("Z", "+00:00"))
                            if created_date < cutoff_date:
                                age_days = (datetime.now() - created_date).days
                                old_keys.append(f"{username} ({age_days} days old)")
                        except:
                            pass

        if old_keys:
            self.add_finding(
                "1.13",
                "Access keys not rotated",
                "FAIL",
                f"Access keys older than 90 days: {', '.join(old_keys)}",
                "MEDIUM"
            )
        else:
            self.add_finding(
                "1.13",
                "All access keys rotated",
                "PASS",
                "All active access keys are less than 90 days old"
            )

    def check_1_14_users_receive_permissions_via_groups(self):
        """CIS 1.14: Ensure IAM users receive permissions only through groups"""
        users_with_direct_policies = []

        for user_data in self.data.get("users", []):
            username = user_data.get("user_info", {}).get("UserName")
            policies = user_data.get("policies", {})

            attached = policies.get("attached_policies", [])
            inline = policies.get("inline_policies", [])

            if attached or inline:
                policy_count = len(attached) + len(inline)
                users_with_direct_policies.append(f"{username} ({policy_count} policies)")

        if users_with_direct_policies:
            self.add_finding(
                "1.14",
                "Users have direct policy attachments",
                "FAIL",
                f"Users with direct policies: {', '.join(users_with_direct_policies)}",
                "MEDIUM"
            )
        else:
            self.add_finding(
                "1.14",
                "All users use group-based permissions",
                "PASS",
                "No users have directly attached policies"
            )

    def check_1_15_no_full_admin_policies(self):
        """CIS 1.15: Ensure IAM policies that allow full '*:*' administrative privileges are not attached"""
        admin_policies = self.data.get("admin_policies", [])

        if admin_policies:
            policy_names = [p.get("policy", {}).get("PolicyName") for p in admin_policies]
            self.add_finding(
                "1.15",
                "Full admin policies detected",
                "FAIL",
                f"Policies with *:* permissions: {', '.join(policy_names)}",
                "HIGH"
            )
        else:
            self.add_finding(
                "1.15",
                "No overly permissive policies",
                "PASS",
                "No policies with full *:* administrative privileges found"
            )

    def check_1_16_support_role_exists(self):
        """CIS 1.16: Ensure a support role has been created to manage incidents with AWS Support"""
        support_role = self.data.get("support_role", {})
        roles = support_role.get("policy_roles", [])

        if roles:
            role_names = [r.get("RoleName") for r in roles]
            self.add_finding(
                "1.16",
                "AWS Support role configured",
                "PASS",
                f"Support roles: {', '.join(role_names)}"
            )
        else:
            self.add_finding(
                "1.16",
                "No AWS Support role",
                "FAIL",
                "No role with AWSSupportAccess policy attached",
                "MEDIUM"
            )

    def check_1_19_access_analyzer_enabled(self):
        """CIS 1.19: Ensure that IAM External Access Analyzer is enabled"""
        analyzers = self.data.get("access_analyzer", [])
        active_analyzers = [a for a in analyzers if a.get("status") == "ACTIVE"]

        if active_analyzers:
            self.add_finding(
                "1.19",
                "IAM Access Analyzer enabled",
                "PASS",
                f"Active analyzers: {len(active_analyzers)}"
            )
        else:
            self.add_finding(
                "1.19",
                "IAM Access Analyzer not enabled",
                "FAIL",
                "No active IAM Access Analyzer found",
                "MEDIUM"
            )

    def check_1_21_cloudshell_access_restricted(self):
        """CIS 1.21: Ensure access to AWSCloudShellFullAccess is restricted"""
        cloudshell = self.data.get("cloudshell_access", {})
        entities = (
            cloudshell.get("policy_roles", []) +
            cloudshell.get("policy_users", []) +
            cloudshell.get("policy_groups", [])
        )

        if entities:
            self.add_finding(
                "1.21",
                "CloudShell access not restricted",
                "FAIL",
                f"Entities with CloudShell access: {len(entities)}",
                "LOW"
            )
        else:
            self.add_finding(
                "1.21",
                "CloudShell access restricted",
                "PASS",
                "No entities using AWSCloudShellFullAccess policy"
            )

    def analyze_all(self):
        """Run all compliance checks"""
        print("="*60)
        print("Starting IAM compliance analysis...")
        print("="*60)

        self.check_1_3_root_access_keys()
        self.check_1_4_root_mfa()
        self.check_1_7_password_length()
        self.check_1_8_password_reuse()
        self.check_1_9_user_mfa()
        self.check_1_11_unused_credentials()
        self.check_1_12_single_access_key()
        self.check_1_13_access_key_rotation()
        self.check_1_14_users_receive_permissions_via_groups()
        self.check_1_15_no_full_admin_policies()
        self.check_1_16_support_role_exists()
        self.check_1_19_access_analyzer_enabled()
        self.check_1_21_cloudshell_access_restricted()

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

        # Also save as CSV
        self.save_csv(filename.replace('.json', '.csv'))

    def save_csv(self, filename: str):
        """Save findings to CSV file for easy Excel analysis"""
        if not self.findings:
            return

        # Convert findings to DataFrame
        df = pd.DataFrame(self.findings)

        # Reorder columns for better readability
        columns = ['control', 'title', 'status', 'severity', 'details', 'timestamp']
        df = df[columns]

        # Sort by control number (treat as string to preserve order)
        df = df.sort_values('control')

        # Save to CSV
        df.to_csv(filename, index=False)
        print(f"CSV report saved: {filename}")

        print(f"Report saved to: {filename}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Analyze IAM data for CIS compliance")
    parser.add_argument("--input", required=True, help="Input data file from IAM collector")
    parser.add_argument("--output", default="iam_compliance_report.json", help="Output report file")

    args = parser.parse_args()

    analyzer = IAMAnalyzer(args.input)
    analyzer.analyze_all()
    analyzer.save_report(args.output)
