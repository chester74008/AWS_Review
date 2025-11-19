#!/usr/bin/env python3
"""
Logging and Monitoring Compliance Analyzer for CIS AWS Benchmark
Analyzes CloudTrail, Config, VPC Flow Logs, and KMS data against CIS controls
"""

import json
from datetime import datetime
from typing import Dict, List, Any


class LoggingAnalyzer:
    """Analyzes Logging and Monitoring data for CIS compliance"""

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

    # ===== CloudTrail Controls =====

    def check_3_1_cloudtrail_all_regions(self):
        """CIS 3.1: Ensure CloudTrail is enabled in all regions"""
        cloudtrail_data = self.data.get("cloudtrail", {})

        multi_region_trails = []
        has_multi_region = False

        for region, data in cloudtrail_data.items():
            trails = data.get("trails", [])

            for trail_info in trails:
                trail = trail_info.get("trail_info", {})
                status = trail_info.get("status", {})

                is_multi_region = trail.get("IsMultiRegionTrail", False)
                is_logging = status.get("IsLogging", False)

                if is_multi_region and is_logging:
                    has_multi_region = True
                    multi_region_trails.append(trail.get("Name", "Unknown"))

        if has_multi_region:
            self.add_finding(
                "3.1",
                "CloudTrail enabled in all regions",
                "PASS",
                f"Multi-region trails found: {', '.join(multi_region_trails)}"
            )
        else:
            self.add_finding(
                "3.1",
                "CloudTrail not enabled in all regions",
                "FAIL",
                "No multi-region CloudTrail trail found that is actively logging",
                "CRITICAL"
            )

    def check_3_2_cloudtrail_log_validation(self):
        """CIS 3.2: Ensure CloudTrail log file validation is enabled"""
        cloudtrail_data = self.data.get("cloudtrail", {})

        trails_without_validation = []
        total_trails = 0

        for region, data in cloudtrail_data.items():
            trails = data.get("trails", [])

            for trail_info in trails:
                trail = trail_info.get("trail_info", {})
                total_trails += 1

                trail_name = trail.get("Name", "Unknown")
                log_validation = trail.get("LogFileValidationEnabled", False)

                if not log_validation:
                    trails_without_validation.append(f"{trail_name} ({region})")

        if total_trails == 0:
            self.add_finding(
                "3.2",
                "No CloudTrail trails to check",
                "FAIL",
                "No CloudTrail trails found",
                "CRITICAL"
            )
        elif trails_without_validation:
            self.add_finding(
                "3.2",
                "CloudTrail log validation not enabled",
                "FAIL",
                f"Trails without validation: {', '.join(trails_without_validation)}",
                "MEDIUM"
            )
        else:
            self.add_finding(
                "3.2",
                "CloudTrail log validation enabled",
                "PASS",
                f"All {total_trails} trails have log file validation enabled"
            )

    def check_3_3_config_enabled(self):
        """CIS 3.3: Ensure AWS Config is enabled in all regions"""
        config_data = self.data.get("config", {})
        regions = self.data.get("regions", [])

        regions_without_config = []
        regions_with_config = []

        for region in regions:
            region_config = config_data.get(region, {})
            recorders = region_config.get("recorders", [])
            recorder_status = region_config.get("recorder_status", [])

            has_recording = False
            for status in recorder_status:
                if status.get("recording", False):
                    has_recording = True
                    break

            if has_recording and recorders:
                regions_with_config.append(region)
            else:
                regions_without_config.append(region)

        if regions_without_config:
            self.add_finding(
                "3.3",
                "AWS Config not enabled in all regions",
                "FAIL",
                f"Regions without Config: {', '.join(regions_without_config[:5])}",
                "HIGH"
            )
        else:
            self.add_finding(
                "3.3",
                "AWS Config enabled in all regions",
                "PASS",
                f"AWS Config is recording in all {len(regions_with_config)} regions"
            )

    def check_3_5_cloudtrail_kms_encryption(self):
        """CIS 3.5: Ensure CloudTrail logs are encrypted with KMS"""
        cloudtrail_data = self.data.get("cloudtrail", {})

        trails_without_kms = []
        total_trails = 0

        for region, data in cloudtrail_data.items():
            trails = data.get("trails", [])

            for trail_info in trails:
                trail = trail_info.get("trail_info", {})
                total_trails += 1

                trail_name = trail.get("Name", "Unknown")
                kms_key_id = trail.get("KmsKeyId")

                if not kms_key_id:
                    trails_without_kms.append(f"{trail_name} ({region})")

        if trails_without_kms:
            self.add_finding(
                "3.5",
                "CloudTrail logs not encrypted with KMS",
                "FAIL",
                f"Trails without KMS: {', '.join(trails_without_kms)}",
                "MEDIUM"
            )
        elif total_trails > 0:
            self.add_finding(
                "3.5",
                "CloudTrail logs encrypted with KMS",
                "PASS",
                f"All {total_trails} trails use KMS encryption"
            )

    def check_3_6_kms_key_rotation(self):
        """CIS 3.6: Ensure rotation for customer-created KMS keys is enabled"""
        kms_data = self.data.get("kms", {})

        keys_without_rotation = []
        total_customer_keys = 0

        for region, data in kms_data.items():
            keys = data.get("keys", [])

            for key_info in keys:
                metadata = key_info.get("metadata", {})
                rotation_enabled = key_info.get("rotation_enabled", False)

                key_id = metadata.get("KeyId", "Unknown")
                key_manager = metadata.get("KeyManager", "")
                key_state = metadata.get("KeyState", "")
                key_spec = metadata.get("KeySpec", "")

                # Only check customer-managed symmetric keys
                if key_manager == "CUSTOMER" and key_state == "Enabled" and key_spec == "SYMMETRIC_DEFAULT":
                    total_customer_keys += 1

                    if not rotation_enabled:
                        keys_without_rotation.append(f"{key_id} ({region})")

        if total_customer_keys == 0:
            self.add_finding(
                "3.6",
                "No customer-managed KMS keys to check",
                "PASS",
                "No customer-managed symmetric KMS keys found",
                "LOW"
            )
        elif keys_without_rotation:
            self.add_finding(
                "3.6",
                "KMS key rotation not enabled",
                "FAIL",
                f"Keys without rotation: {', '.join(keys_without_rotation[:5])}",
                "MEDIUM"
            )
        else:
            self.add_finding(
                "3.6",
                "All KMS keys have rotation enabled",
                "PASS",
                f"All {total_customer_keys} customer-managed keys have rotation enabled"
            )

    def check_3_7_vpc_flow_logs(self):
        """CIS 3.7: Ensure VPC flow logging is enabled in all VPCs"""
        vpc_data = self.data.get("vpc_flow_logs", {})

        vpcs_without_flow_logs = []
        total_vpcs = 0

        for region, data in vpc_data.items():
            vpcs = data.get("vpcs", [])
            flow_logs = data.get("flow_logs", [])

            # Create a set of VPC IDs with flow logs
            vpcs_with_logs = set()
            for log in flow_logs:
                resource_id = log.get("ResourceId", "")
                log_status = log.get("FlowLogStatus", "")

                if log_status == "ACTIVE":
                    vpcs_with_logs.add(resource_id)

            # Check each VPC
            for vpc in vpcs:
                total_vpcs += 1
                vpc_id = vpc.get("VpcId", "Unknown")

                if vpc_id not in vpcs_with_logs:
                    vpcs_without_flow_logs.append(f"{vpc_id} ({region})")

        if total_vpcs == 0:
            self.add_finding(
                "3.7",
                "No VPCs to check",
                "PASS",
                "No VPCs found in account",
                "LOW"
            )
        elif vpcs_without_flow_logs:
            self.add_finding(
                "3.7",
                "VPCs without flow logs",
                "FAIL",
                f"VPCs without flow logs: {', '.join(vpcs_without_flow_logs[:5])}",
                "MEDIUM"
            )
        else:
            self.add_finding(
                "3.7",
                "All VPCs have flow logging enabled",
                "PASS",
                f"All {total_vpcs} VPCs have active flow logs"
            )

    def check_3_8_s3_object_write_logging(self):
        """CIS 3.8: Ensure object-level logging for write events is enabled for S3"""
        cloudtrail_data = self.data.get("cloudtrail", {})

        has_s3_write_logging = False
        trails_with_s3_logging = []

        for region, data in cloudtrail_data.items():
            trails = data.get("trails", [])

            for trail_info in trails:
                trail = trail_info.get("trail_info", {})
                event_selectors = trail_info.get("event_selectors", {})

                trail_name = trail.get("Name", "Unknown")
                selectors = event_selectors.get("EventSelectors", [])

                # Check if any event selector has S3 data events for write
                for selector in selectors:
                    data_resources = selector.get("DataResources", [])
                    read_write_type = selector.get("ReadWriteType", "All")

                    for resource in data_resources:
                        resource_type = resource.get("Type", "")
                        values = resource.get("Values", [])

                        # Check for S3 objects and write/all events
                        if resource_type == "AWS::S3::Object":
                            if read_write_type in ["WriteOnly", "All"]:
                                # Check if it covers all buckets
                                if "arn:aws:s3:::*/*" in values or "*" in values:
                                    has_s3_write_logging = True
                                    trails_with_s3_logging.append(trail_name)

        if has_s3_write_logging:
            self.add_finding(
                "3.8",
                "S3 object-level write logging enabled",
                "PASS",
                f"Trails with S3 write logging: {', '.join(set(trails_with_s3_logging))}"
            )
        else:
            self.add_finding(
                "3.8",
                "S3 object-level write logging not enabled",
                "FAIL",
                "No CloudTrail trail found with S3 object-level write event logging",
                "MEDIUM"
            )

    def check_3_9_s3_object_read_logging(self):
        """CIS 3.9: Ensure object-level logging for read events is enabled for S3"""
        cloudtrail_data = self.data.get("cloudtrail", {})

        has_s3_read_logging = False
        trails_with_s3_logging = []

        for region, data in cloudtrail_data.items():
            trails = data.get("trails", [])

            for trail_info in trails:
                trail = trail_info.get("trail_info", {})
                event_selectors = trail_info.get("event_selectors", {})

                trail_name = trail.get("Name", "Unknown")
                selectors = event_selectors.get("EventSelectors", [])

                # Check if any event selector has S3 data events for read
                for selector in selectors:
                    data_resources = selector.get("DataResources", [])
                    read_write_type = selector.get("ReadWriteType", "All")

                    for resource in data_resources:
                        resource_type = resource.get("Type", "")
                        values = resource.get("Values", [])

                        # Check for S3 objects and read/all events
                        if resource_type == "AWS::S3::Object":
                            if read_write_type in ["ReadOnly", "All"]:
                                # Check if it covers all buckets
                                if "arn:aws:s3:::*/*" in values or "*" in values:
                                    has_s3_read_logging = True
                                    trails_with_s3_logging.append(trail_name)

        if has_s3_read_logging:
            self.add_finding(
                "3.9",
                "S3 object-level read logging enabled",
                "PASS",
                f"Trails with S3 read logging: {', '.join(set(trails_with_s3_logging))}"
            )
        else:
            self.add_finding(
                "3.9",
                "S3 object-level read logging not enabled",
                "FAIL",
                "No CloudTrail trail found with S3 object-level read event logging",
                "MEDIUM"
            )

    def analyze_all(self):
        """Run all logging and monitoring compliance checks"""
        print("="*60)
        print("Starting Logging & Monitoring compliance analysis...")
        print("="*60)

        # CloudTrail checks
        self.check_3_1_cloudtrail_all_regions()
        self.check_3_2_cloudtrail_log_validation()
        self.check_3_5_cloudtrail_kms_encryption()
        self.check_3_8_s3_object_write_logging()
        self.check_3_9_s3_object_read_logging()

        # Config checks
        self.check_3_3_config_enabled()

        # KMS checks
        self.check_3_6_kms_key_rotation()

        # VPC checks
        self.check_3_7_vpc_flow_logs()

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

    parser = argparse.ArgumentParser(description="Analyze Logging data for CIS compliance")
    parser.add_argument("--input", required=True, help="Input data file from Logging collector")
    parser.add_argument("--output", default="logging_compliance_report.json", help="Output report file")

    args = parser.parse_args()

    analyzer = LoggingAnalyzer(args.input)
    analyzer.analyze_all()
    analyzer.save_report(args.output)
