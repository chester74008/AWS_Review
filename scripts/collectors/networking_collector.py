#!/usr/bin/env python3
"""
Networking Data Collector for CIS AWS Benchmark
Collects VPC, Security Groups, NACLs, Route Tables, and EC2 metadata configuration
"""

import json
import subprocess
import sys
from datetime import datetime
from typing import Dict, List, Any


class NetworkingCollector:
    """Collects networking configuration data from AWS"""

    def __init__(self, profile: str = "default", region: str = "us-east-1"):
        self.profile = profile
        self.region = region
        self.data = {}

    def run_aws_command(self, command: List[str], region: str = None) -> Dict[str, Any]:
        """Run an AWS CLI command and return JSON output"""
        cmd = ["aws"] + command + ["--profile", self.profile, "--output", "json"]
        if region:
            cmd += ["--region", region]
        else:
            cmd += ["--region", self.region]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=60)
            if result.stdout:
                return json.loads(result.stdout)
            return {}
        except subprocess.CalledProcessError as e:
            print(f"Error running command: {e.stderr}", file=sys.stderr)
            return {}
        except json.JSONDecodeError:
            print(f"Error parsing JSON output", file=sys.stderr)
            return {}
        except subprocess.TimeoutExpired:
            print(f"Command timed out", file=sys.stderr)
            return {}

    def get_all_regions(self) -> List[str]:
        """Get list of all AWS regions"""
        result = self.run_aws_command(["ec2", "describe-regions"])
        return [r["RegionName"] for r in result.get("Regions", [])]

    def collect_vpcs(self, region: str = None) -> List[Dict[str, Any]]:
        """
        CIS 5.5: Collect VPCs
        """
        print(f"Collecting VPCs in {region or self.region}...")
        result = self.run_aws_command(["ec2", "describe-vpcs"], region)
        return result.get("Vpcs", [])

    def collect_security_groups(self, region: str = None) -> List[Dict[str, Any]]:
        """
        CIS 5.3, 5.4, 5.5: Collect Security Groups
        """
        print(f"Collecting Security Groups in {region or self.region}...")
        result = self.run_aws_command(["ec2", "describe-security-groups"], region)
        return result.get("SecurityGroups", [])

    def collect_network_acls(self, region: str = None) -> List[Dict[str, Any]]:
        """
        CIS 5.2: Collect Network ACLs
        """
        print(f"Collecting Network ACLs in {region or self.region}...")
        result = self.run_aws_command(["ec2", "describe-network-acls"], region)
        return result.get("NetworkAcls", [])

    def collect_route_tables(self, region: str = None) -> List[Dict[str, Any]]:
        """
        CIS 5.6: Collect Route Tables
        """
        print(f"Collecting Route Tables in {region or self.region}...")
        result = self.run_aws_command(["ec2", "describe-route-tables"], region)
        return result.get("RouteTables", [])

    def collect_ec2_instances(self, region: str = None) -> List[Dict[str, Any]]:
        """
        CIS 5.7: Collect EC2 instances (for metadata service configuration)
        """
        print(f"Collecting EC2 Instances in {region or self.region}...")
        result = self.run_aws_command(["ec2", "describe-instances"], region)

        instances = []
        for reservation in result.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                instances.append(instance)

        return instances

    def collect_ebs_encryption_by_default(self, region: str = None) -> Dict[str, Any]:
        """
        CIS 5.1.1: Check if EBS encryption by default is enabled
        """
        result = self.run_aws_command(["ec2", "get-ebs-encryption-by-default"], region)
        return result

    def collect_all(self, all_regions: bool = False) -> Dict[str, Any]:
        """Collect all networking data"""
        print("="*60)
        print("Starting Networking data collection...")
        print("="*60)

        regions = [self.region]
        if all_regions:
            regions = self.get_all_regions()
            print(f"Collecting data from {len(regions)} regions...")

        self.data = {
            "collection_time": datetime.now().isoformat(),
            "profile": self.profile,
            "regions": regions,
            "vpcs": {},
            "security_groups": {},
            "network_acls": {},
            "route_tables": {},
            "ec2_instances": {},
            "ebs_encryption_default": {}
        }

        # Collect data per region
        for region in regions:
            print(f"\nCollecting data for region: {region}")

            # VPCs
            vpcs = self.collect_vpcs(region)
            self.data["vpcs"][region] = vpcs

            # Security Groups
            security_groups = self.collect_security_groups(region)
            self.data["security_groups"][region] = security_groups

            # Network ACLs
            network_acls = self.collect_network_acls(region)
            self.data["network_acls"][region] = network_acls

            # Route Tables
            route_tables = self.collect_route_tables(region)
            self.data["route_tables"][region] = route_tables

            # EC2 Instances
            ec2_instances = self.collect_ec2_instances(region)
            self.data["ec2_instances"][region] = ec2_instances

            # EBS Encryption by Default
            ebs_encryption = self.collect_ebs_encryption_by_default(region)
            self.data["ebs_encryption_default"][region] = ebs_encryption

        print("\nData collection complete!")
        return self.data

    def save_to_file(self, filename: str):
        """Save collected data to JSON file"""
        with open(filename, 'w') as f:
            json.dump(self.data, f, indent=2, default=str)
        print(f"Data saved to: {filename}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Collect networking data from AWS")
    parser.add_argument("--profile", default="default", help="AWS profile to use")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--all-regions", action="store_true", help="Collect from all regions")
    parser.add_argument("--output", default="networking_data.json", help="Output file")

    args = parser.parse_args()

    collector = NetworkingCollector(profile=args.profile, region=args.region)
    collector.collect_all(all_regions=args.all_regions)
    collector.save_to_file(args.output)
