#!/usr/bin/env python3
"""
Logging and Monitoring Collector for CIS AWS Benchmark
Collects CloudTrail, CloudWatch, Config, and VPC Flow Logs data
"""

import subprocess
import json
import sys
from datetime import datetime
from typing import Dict, List, Any


class LoggingCollector:
    """Collects logging and monitoring configuration data"""

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

    # ===== CloudTrail Controls =====

    def collect_cloudtrail_trails(self, region: str = None) -> List[Dict[str, Any]]:
        """
        CIS 3.1: List all CloudTrail trails
        """
        print(f"Collecting CloudTrail trails in {region or self.region}...")
        result = self.run_aws_command(["cloudtrail", "describe-trails"], region)
        return result.get("trailList", [])

    def collect_trail_status(self, trail_name: str, region: str = None) -> Dict[str, Any]:
        """
        Get trail logging status
        """
        return self.run_aws_command(["cloudtrail", "get-trail-status", "--name", trail_name], region)

    def collect_trail_event_selectors(self, trail_name: str, region: str = None) -> Dict[str, Any]:
        """
        CIS 3.8, 3.9: Get trail event selectors for S3 data events
        """
        return self.run_aws_command(["cloudtrail", "get-event-selectors", "--trail-name", trail_name], region)

    # ===== AWS Config =====

    def collect_config_recorders(self, region: str = None) -> List[Dict[str, Any]]:
        """
        CIS 3.3: Check if AWS Config is enabled
        """
        print(f"Collecting AWS Config recorders in {region or self.region}...")
        result = self.run_aws_command(["configservice", "describe-configuration-recorders"], region)
        return result.get("ConfigurationRecorders", [])

    def collect_config_recorder_status(self, region: str = None) -> List[Dict[str, Any]]:
        """
        Get Config recorder status
        """
        result = self.run_aws_command(["configservice", "describe-configuration-recorder-status"], region)
        return result.get("ConfigurationRecordersStatus", [])

    def collect_config_delivery_channels(self, region: str = None) -> List[Dict[str, Any]]:
        """
        Get Config delivery channels
        """
        result = self.run_aws_command(["configservice", "describe-delivery-channels"], region)
        return result.get("DeliveryChannels", [])

    # ===== VPC Flow Logs =====

    def collect_vpcs(self, region: str = None) -> List[Dict[str, Any]]:
        """
        CIS 3.7: List all VPCs
        """
        print(f"Collecting VPCs in {region or self.region}...")
        result = self.run_aws_command(["ec2", "describe-vpcs"], region)
        return result.get("Vpcs", [])

    def collect_flow_logs(self, region: str = None) -> List[Dict[str, Any]]:
        """
        CIS 3.7: Get VPC Flow Logs
        """
        result = self.run_aws_command(["ec2", "describe-flow-logs"], region)
        return result.get("FlowLogs", [])

    # ===== KMS =====

    def collect_kms_keys(self, region: str = None) -> List[Dict[str, Any]]:
        """
        CIS 3.6: List KMS keys for rotation check
        """
        print(f"Collecting KMS keys in {region or self.region}...")
        result = self.run_aws_command(["kms", "list-keys"], region)
        keys = result.get("Keys", [])

        # Get detailed info for each key
        detailed_keys = []
        for key in keys:
            key_id = key.get("KeyId")
            metadata = self.run_aws_command(["kms", "describe-key", "--key-id", key_id], region)
            rotation_status = self.run_aws_command(["kms", "get-key-rotation-status", "--key-id", key_id], region)

            detailed_keys.append({
                "key_info": key,
                "metadata": metadata.get("KeyMetadata", {}),
                "rotation_enabled": rotation_status.get("KeyRotationEnabled", False)
            })

        return detailed_keys

    # ===== CloudWatch Logs & Metric Filters =====

    def collect_log_groups(self, region: str = None) -> List[Dict[str, Any]]:
        """
        CIS 4.x: List CloudWatch Log Groups
        """
        print(f"Collecting CloudWatch Log Groups in {region or self.region}...")
        result = self.run_aws_command(["logs", "describe-log-groups"], region)
        return result.get("logGroups", [])

    def collect_metric_filters(self, log_group_name: str, region: str = None) -> List[Dict[str, Any]]:
        """
        CIS 4.x: Get metric filters for a log group
        """
        result = self.run_aws_command(
            ["logs", "describe-metric-filters", "--log-group-name", log_group_name],
            region
        )
        return result.get("metricFilters", [])

    def collect_cloudwatch_alarms(self, region: str = None) -> List[Dict[str, Any]]:
        """
        CIS 4.x: List CloudWatch Alarms
        """
        print(f"Collecting CloudWatch Alarms in {region or self.region}...")
        result = self.run_aws_command(["cloudwatch", "describe-alarms"], region)
        return result.get("MetricAlarms", [])

    def collect_all(self, all_regions: bool = False) -> Dict[str, Any]:
        """Collect all logging and monitoring data"""
        print("="*60)
        print("Starting Logging & Monitoring data collection...")
        print("="*60)

        regions = [self.region]
        if all_regions:
            regions = self.get_all_regions()
            print(f"Collecting data from {len(regions)} regions...")

        self.data = {
            "collection_time": datetime.now().isoformat(),
            "profile": self.profile,
            "regions": regions,
            "cloudtrail": {},
            "config": {},
            "vpc_flow_logs": {},
            "kms": {},
            "cloudwatch": {}
        }

        # Collect data per region
        for region in regions:
            print(f"\nCollecting data for region: {region}")

            # CloudTrail
            trails = self.collect_cloudtrail_trails(region)
            trail_details = []

            for trail in trails:
                trail_name = trail.get("Name")
                trail_arn = trail.get("TrailARN")

                print(f"  Collecting details for trail: {trail_name}")

                trail_data = {
                    "trail_info": trail,
                    "status": self.collect_trail_status(trail_arn, region),
                    "event_selectors": self.collect_trail_event_selectors(trail_name, region)
                }
                trail_details.append(trail_data)

            self.data["cloudtrail"][region] = {
                "trails": trail_details
            }

            # AWS Config
            config_recorders = self.collect_config_recorders(region)
            config_status = self.collect_config_recorder_status(region)
            config_channels = self.collect_config_delivery_channels(region)

            self.data["config"][region] = {
                "recorders": config_recorders,
                "recorder_status": config_status,
                "delivery_channels": config_channels
            }

            # VPC Flow Logs
            vpcs = self.collect_vpcs(region)
            flow_logs = self.collect_flow_logs(region)

            self.data["vpc_flow_logs"][region] = {
                "vpcs": vpcs,
                "flow_logs": flow_logs
            }

            # KMS Keys
            kms_keys = self.collect_kms_keys(region)
            self.data["kms"][region] = {
                "keys": kms_keys
            }

            # CloudWatch
            log_groups = self.collect_log_groups(region)
            alarms = self.collect_cloudwatch_alarms(region)

            # Get metric filters for each log group
            log_group_details = []
            for lg in log_groups:
                lg_name = lg.get("logGroupName")
                metric_filters = self.collect_metric_filters(lg_name, region)

                log_group_details.append({
                    "log_group": lg,
                    "metric_filters": metric_filters
                })

            self.data["cloudwatch"][region] = {
                "log_groups": log_group_details,
                "alarms": alarms
            }

        print("\nLogging & Monitoring data collection complete!")
        return self.data

    def save_to_file(self, filename: str):
        """Save collected data to JSON file"""
        with open(filename, 'w') as f:
            json.dump(self.data, f, indent=2, default=str)
        print(f"Data saved to: {filename}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Collect Logging/Monitoring data for CIS AWS Benchmark")
    parser.add_argument("--profile", default="default", help="AWS profile to use")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--all-regions", action="store_true", help="Collect from all regions")
    parser.add_argument("--output", default="logging_data.json", help="Output file")

    args = parser.parse_args()

    collector = LoggingCollector(profile=args.profile, region=args.region)
    collector.collect_all(all_regions=args.all_regions)
    collector.save_to_file(args.output)
