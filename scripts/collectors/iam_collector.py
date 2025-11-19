#!/usr/bin/env python3
"""
IAM Data Collector for CIS AWS Benchmark
Collects IAM-related data using AWS CLI commands
"""

import subprocess
import json
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Any


class IAMCollector:
    """Collects IAM configuration data from AWS account"""

    def __init__(self, profile: str = "default", region: str = "us-east-1"):
        self.profile = profile
        self.region = region
        self.data = {}

    def run_aws_command(self, command: List[str]) -> Dict[str, Any]:
        """Execute AWS CLI command and return JSON output"""
        cmd = ["aws"] + command + ["--profile", self.profile, "--output", "json"]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return json.loads(result.stdout) if result.stdout else {}
        except subprocess.CalledProcessError as e:
            print(f"Error running command {' '.join(cmd)}: {e.stderr}", file=sys.stderr)
            return {}
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON: {e}", file=sys.stderr)
            return {}

    def collect_credential_report(self) -> Dict[str, Any]:
        """
        CIS 1.3, 1.4, 1.6, 1.9, 1.11, 1.13: Generate and retrieve credential report
        """
        print("Generating IAM credential report...")

        # Generate the report
        self.run_aws_command(["iam", "generate-credential-report"])

        # Wait a moment for it to be ready
        import time
        time.sleep(2)

        # Get the report
        result = self.run_aws_command(["iam", "get-credential-report", "--query", "Content"])

        if result:
            # The content is base64 encoded
            import base64
            import csv
            import io

            content = base64.b64decode(result).decode('utf-8')
            reader = csv.DictReader(io.StringIO(content))
            credentials = list(reader)

            return {
                "generated_time": datetime.now().isoformat(),
                "credentials": credentials
            }

        return {}

    def collect_password_policy(self) -> Dict[str, Any]:
        """
        CIS 1.7, 1.8: Get account password policy
        """
        print("Collecting IAM password policy...")
        return self.run_aws_command(["iam", "get-account-password-policy"])

    def collect_users(self) -> List[Dict[str, Any]]:
        """
        CIS 1.10, 1.12, 1.14: List all IAM users
        """
        print("Collecting IAM users...")
        result = self.run_aws_command(["iam", "list-users"])
        return result.get("Users", [])

    def collect_user_policies(self, username: str) -> Dict[str, Any]:
        """
        CIS 1.14: Check if user has direct policy attachments
        """
        attached = self.run_aws_command(["iam", "list-attached-user-policies", "--user-name", username])
        inline = self.run_aws_command(["iam", "list-user-policies", "--user-name", username])

        return {
            "attached_policies": attached.get("AttachedPolicies", []),
            "inline_policies": inline.get("PolicyNames", [])
        }

    def collect_user_access_keys(self, username: str) -> List[Dict[str, Any]]:
        """
        CIS 1.12, 1.13: Get access keys for user
        """
        result = self.run_aws_command(["iam", "list-access-keys", "--user-name", username])
        return result.get("AccessKeyMetadata", [])

    def collect_user_mfa_devices(self, username: str) -> List[Dict[str, Any]]:
        """
        CIS 1.9: Get MFA devices for user
        """
        result = self.run_aws_command(["iam", "list-mfa-devices", "--user-name", username])
        return result.get("MFADevices", [])

    def collect_admin_policies(self) -> List[Dict[str, Any]]:
        """
        CIS 1.15: Find policies with full admin privileges
        """
        print("Checking for overly permissive policies...")
        result = self.run_aws_command(["iam", "list-policies", "--only-attached", "--scope", "Local"])
        policies = result.get("Policies", [])

        admin_policies = []
        for policy in policies:
            # Get the policy version
            policy_arn = policy.get("Arn")
            version_id = policy.get("DefaultVersionId")

            if policy_arn and version_id:
                version = self.run_aws_command([
                    "iam", "get-policy-version",
                    "--policy-arn", policy_arn,
                    "--version-id", version_id
                ])

                # Check if policy has "*:*" permissions
                policy_doc = version.get("PolicyVersion", {}).get("Document", {})
                statements = policy_doc.get("Statement", [])

                for statement in statements:
                    if isinstance(statement, dict):
                        actions = statement.get("Action", [])
                        resources = statement.get("Resource", [])
                        effect = statement.get("Effect", "")

                        if effect == "Allow":
                            if "*" in actions or (isinstance(actions, str) and actions == "*"):
                                if "*" in resources or (isinstance(resources, str) and resources == "*"):
                                    admin_policies.append({
                                        "policy": policy,
                                        "statement": statement
                                    })

        return admin_policies

    def collect_support_role(self) -> Dict[str, Any]:
        """
        CIS 1.16: Check if AWS Support role exists
        """
        print("Checking for AWS Support role...")
        result = self.run_aws_command([
            "iam", "list-entities-for-policy",
            "--policy-arn", "arn:aws:iam::aws:policy/AWSSupportAccess"
        ])

        return {
            "policy_roles": result.get("PolicyRoles", []),
            "policy_users": result.get("PolicyUsers", []),
            "policy_groups": result.get("PolicyGroups", [])
        }

    def collect_server_certificates(self) -> List[Dict[str, Any]]:
        """
        CIS 1.18: List IAM SSL/TLS certificates
        """
        print("Collecting IAM server certificates...")
        result = self.run_aws_command(["iam", "list-server-certificates"])
        return result.get("ServerCertificateMetadataList", [])

    def collect_access_analyzer(self) -> List[Dict[str, Any]]:
        """
        CIS 1.19: Check IAM Access Analyzer status
        """
        print("Checking IAM Access Analyzer...")
        result = self.run_aws_command(["accessanalyzer", "list-analyzers"])
        return result.get("analyzers", [])

    def collect_cloudshell_access(self) -> Dict[str, Any]:
        """
        CIS 1.21: Check AWSCloudShellFullAccess policy usage
        """
        print("Checking CloudShell access...")
        result = self.run_aws_command([
            "iam", "list-entities-for-policy",
            "--policy-arn", "arn:aws:iam::aws:policy/AWSCloudShellFullAccess"
        ])

        return {
            "policy_roles": result.get("PolicyRoles", []),
            "policy_users": result.get("PolicyUsers", []),
            "policy_groups": result.get("PolicyGroups", [])
        }

    def collect_all(self) -> Dict[str, Any]:
        """Collect all IAM data"""
        print("="*60)
        print("Starting IAM data collection...")
        print("="*60)

        self.data = {
            "collection_time": datetime.now().isoformat(),
            "profile": self.profile,
            "region": self.region,
            "credential_report": self.collect_credential_report(),
            "password_policy": self.collect_password_policy(),
            "users": [],
            "admin_policies": self.collect_admin_policies(),
            "support_role": self.collect_support_role(),
            "server_certificates": self.collect_server_certificates(),
            "access_analyzer": self.collect_access_analyzer(),
            "cloudshell_access": self.collect_cloudshell_access()
        }

        # Collect detailed info for each user
        users = self.collect_users()
        for user in users:
            username = user.get("UserName")
            print(f"Collecting data for user: {username}")

            user_data = {
                "user_info": user,
                "policies": self.collect_user_policies(username),
                "access_keys": self.collect_user_access_keys(username),
                "mfa_devices": self.collect_user_mfa_devices(username)
            }
            self.data["users"].append(user_data)

        print("\nIAM data collection complete!")
        return self.data

    def save_to_file(self, filename: str):
        """Save collected data to JSON file"""
        with open(filename, 'w') as f:
            json.dump(self.data, f, indent=2, default=str)
        print(f"Data saved to: {filename}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Collect IAM data for CIS AWS Benchmark audit")
    parser.add_argument("--profile", default="default", help="AWS profile to use")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--output", default="iam_data.json", help="Output file")

    args = parser.parse_args()

    collector = IAMCollector(profile=args.profile, region=args.region)
    collector.collect_all()
    collector.save_to_file(args.output)
