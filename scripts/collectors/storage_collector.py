#!/usr/bin/env python3
"""
Storage Data Collector for CIS AWS Benchmark (S3, RDS, EFS)
Collects storage-related data using AWS CLI commands
"""

import subprocess
import json
import sys
from datetime import datetime
from typing import Dict, List, Any


class StorageCollector:
    """Collects S3, RDS, and EFS configuration data"""

    def __init__(self, profile: str = "default", region: str = "us-east-1"):
        self.profile = profile
        self.region = region
        self.data = {}

    def run_aws_command(self, command: List[str], region: str = None) -> Dict[str, Any]:
        """Execute AWS CLI command and return JSON output"""
        use_region = region if region else self.region
        cmd = ["aws"] + command + ["--profile", self.profile, "--region", use_region, "--output", "json"]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return json.loads(result.stdout) if result.stdout else {}
        except subprocess.CalledProcessError as e:
            print(f"Error running command: {e.stderr}", file=sys.stderr)
            return {}
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON: {e}", file=sys.stderr)
            return {}

    def get_all_regions(self) -> List[str]:
        """Get list of all AWS regions"""
        result = self.run_aws_command(["ec2", "describe-regions", "--query", "Regions[].RegionName"])
        return result if isinstance(result, list) else []

    # ===== S3 Controls =====

    def collect_s3_buckets(self) -> List[Dict[str, Any]]:
        """
        CIS 2.1.x: List all S3 buckets
        """
        print("Collecting S3 buckets...")
        result = self.run_aws_command(["s3api", "list-buckets"])
        return result.get("Buckets", [])

    def collect_bucket_policy(self, bucket_name: str) -> Dict[str, Any]:
        """
        CIS 2.1.1: Get bucket policy to check for HTTPS enforcement
        """
        result = self.run_aws_command(["s3api", "get-bucket-policy", "--bucket", bucket_name])

        if result and "Policy" in result:
            try:
                policy = json.loads(result["Policy"])
                return policy
            except:
                return {}
        return {}

    def collect_bucket_versioning(self, bucket_name: str) -> Dict[str, Any]:
        """
        CIS 2.1.2: Check if versioning and MFA Delete are enabled
        """
        return self.run_aws_command(["s3api", "get-bucket-versioning", "--bucket", bucket_name])

    def collect_bucket_encryption(self, bucket_name: str) -> Dict[str, Any]:
        """
        Check bucket encryption configuration
        """
        return self.run_aws_command(["s3api", "get-bucket-encryption", "--bucket", bucket_name])

    def collect_bucket_public_access_block(self, bucket_name: str) -> Dict[str, Any]:
        """
        CIS 2.1.4: Check Block Public Access settings
        """
        return self.run_aws_command(["s3api", "get-public-access-block", "--bucket", bucket_name])

    def collect_bucket_acl(self, bucket_name: str) -> Dict[str, Any]:
        """
        Check bucket ACL for public access
        """
        return self.run_aws_command(["s3api", "get-bucket-acl", "--bucket", bucket_name])

    def collect_macie_status(self) -> Dict[str, Any]:
        """
        CIS 2.1.3: Check if Macie is enabled
        """
        print("Checking Macie status...")
        result = self.run_aws_command(["macie2", "get-macie-session"])
        return result

    # ===== RDS Controls =====

    def collect_rds_instances(self, region: str = None) -> List[Dict[str, Any]]:
        """
        CIS 2.2.x: List all RDS instances
        """
        print(f"Collecting RDS instances in {region or self.region}...")
        result = self.run_aws_command(["rds", "describe-db-instances"], region)
        return result.get("DBInstances", [])

    def collect_rds_snapshots(self, region: str = None) -> List[Dict[str, Any]]:
        """
        Check RDS snapshots
        """
        result = self.run_aws_command(["rds", "describe-db-snapshots", "--snapshot-type", "manual"], region)
        return result.get("DBSnapshots", [])

    # ===== EFS Controls =====

    def collect_efs_filesystems(self, region: str = None) -> List[Dict[str, Any]]:
        """
        CIS 2.3.1: List all EFS file systems
        """
        print(f"Collecting EFS file systems in {region or self.region}...")
        result = self.run_aws_command(["efs", "describe-file-systems"], region)
        return result.get("FileSystems", [])

    def collect_all(self, all_regions: bool = False) -> Dict[str, Any]:
        """Collect all storage data"""
        print("="*60)
        print("Starting Storage data collection...")
        print("="*60)

        regions = [self.region]
        if all_regions:
            regions = self.get_all_regions()
            print(f"Collecting data from {len(regions)} regions...")

        self.data = {
            "collection_time": datetime.now().isoformat(),
            "profile": self.profile,
            "regions": regions,
            "s3": {
                "buckets": [],
                "macie_status": self.collect_macie_status()
            },
            "rds": {},
            "efs": {}
        }

        # Collect S3 data (S3 is global, but bucket configs need region)
        buckets = self.collect_s3_buckets()
        for bucket in buckets:
            bucket_name = bucket.get("Name")
            print(f"Collecting data for S3 bucket: {bucket_name}")

            bucket_data = {
                "name": bucket_name,
                "creation_date": bucket.get("CreationDate"),
                "policy": self.collect_bucket_policy(bucket_name),
                "versioning": self.collect_bucket_versioning(bucket_name),
                "encryption": self.collect_bucket_encryption(bucket_name),
                "public_access_block": self.collect_bucket_public_access_block(bucket_name),
                "acl": self.collect_bucket_acl(bucket_name)
            }
            self.data["s3"]["buckets"].append(bucket_data)

        # Collect regional data (RDS, EFS)
        for region in regions:
            print(f"\nCollecting data for region: {region}")

            # RDS
            rds_instances = self.collect_rds_instances(region)
            rds_snapshots = self.collect_rds_snapshots(region)

            self.data["rds"][region] = {
                "instances": rds_instances,
                "snapshots": rds_snapshots
            }

            # EFS
            efs_filesystems = self.collect_efs_filesystems(region)
            self.data["efs"][region] = {
                "filesystems": efs_filesystems
            }

        print("\nStorage data collection complete!")
        return self.data

    def save_to_file(self, filename: str):
        """Save collected data to JSON file"""
        with open(filename, 'w') as f:
            json.dump(self.data, f, indent=2, default=str)
        print(f"Data saved to: {filename}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Collect Storage data for CIS AWS Benchmark audit")
    parser.add_argument("--profile", default="default", help="AWS profile to use")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--all-regions", action="store_true", help="Collect from all regions")
    parser.add_argument("--output", default="storage_data.json", help="Output file")

    args = parser.parse_args()

    collector = StorageCollector(profile=args.profile, region=args.region)
    collector.collect_all(all_regions=args.all_regions)
    collector.save_to_file(args.output)
