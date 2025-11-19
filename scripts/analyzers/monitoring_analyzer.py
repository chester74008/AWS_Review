#!/usr/bin/env python3
"""
CloudWatch Monitoring Compliance Analyzer for CIS AWS Benchmark
Analyzes CloudWatch metric filters and alarms against CIS controls 4.1-4.16
"""

import json
import pandas as pd
import re
from datetime import datetime
from typing import Dict, List, Any


class MonitoringAnalyzer:
    """Analyzes CloudWatch Monitoring data for CIS compliance"""

    def __init__(self, data_file: str):
        with open(data_file, 'r') as f:
            self.data = json.load(f)
        self.findings = []

        # CIS-recommended metric filter patterns
        # These are simplified patterns - actual patterns may vary slightly
        self.required_patterns = {
            "4.1": {
                "title": "Unauthorized API calls monitored",
                "pattern_keywords": ["errorCode", "UnauthorizedOperation", "AccessDenied"],
                "description": "Detects unauthorized API calls"
            },
            "4.2": {
                "title": "Console sign-in without MFA monitored",
                "pattern_keywords": ["ConsoleLogin", "mfaAuthenticated", "false"],
                "description": "Detects console login without MFA"
            },
            "4.3": {
                "title": "Root account usage monitored",
                "pattern_keywords": ["userIdentity.type", "Root", "invokedBy"],
                "description": "Detects root account usage"
            },
            "4.4": {
                "title": "IAM policy changes monitored",
                "pattern_keywords": ["DeleteGroupPolicy", "DeleteRolePolicy", "DeleteUserPolicy",
                                     "PutGroupPolicy", "PutRolePolicy", "PutUserPolicy",
                                     "CreatePolicy", "DeletePolicy", "CreatePolicyVersion",
                                     "DeletePolicyVersion", "AttachRolePolicy", "DetachRolePolicy",
                                     "AttachUserPolicy", "DetachUserPolicy", "AttachGroupPolicy", "DetachGroupPolicy"],
                "description": "Detects IAM policy changes"
            },
            "4.5": {
                "title": "CloudTrail configuration changes monitored",
                "pattern_keywords": ["CreateTrail", "UpdateTrail", "DeleteTrail",
                                     "StartLogging", "StopLogging"],
                "description": "Detects CloudTrail configuration changes"
            },
            "4.6": {
                "title": "Console authentication failures monitored",
                "pattern_keywords": ["ConsoleLogin", "Failed authentication"],
                "description": "Detects failed console authentication attempts"
            },
            "4.7": {
                "title": "CMK disabling/deletion monitored",
                "pattern_keywords": ["DisableKey", "ScheduleKeyDeletion"],
                "description": "Detects disabling or scheduled deletion of customer managed keys"
            },
            "4.8": {
                "title": "S3 bucket policy changes monitored",
                "pattern_keywords": ["PutBucketAcl", "PutBucketPolicy", "PutBucketCors",
                                     "PutBucketLifecycle", "PutBucketReplication",
                                     "DeleteBucketPolicy", "DeleteBucketCors",
                                     "DeleteBucketLifecycle", "DeleteBucketReplication"],
                "description": "Detects S3 bucket policy changes"
            },
            "4.9": {
                "title": "AWS Config configuration changes monitored",
                "pattern_keywords": ["PutConfigurationRecorder", "StopConfigurationRecorder",
                                     "DeleteDeliveryChannel", "PutDeliveryChannel"],
                "description": "Detects AWS Config configuration changes"
            },
            "4.10": {
                "title": "Security group changes monitored",
                "pattern_keywords": ["AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
                                     "RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress",
                                     "CreateSecurityGroup", "DeleteSecurityGroup"],
                "description": "Detects security group changes"
            },
            "4.11": {
                "title": "NACL changes monitored",
                "pattern_keywords": ["CreateNetworkAcl", "CreateNetworkAclEntry",
                                     "DeleteNetworkAcl", "DeleteNetworkAclEntry",
                                     "ReplaceNetworkAclEntry", "ReplaceNetworkAclAssociation"],
                "description": "Detects Network ACL changes"
            },
            "4.12": {
                "title": "Network gateway changes monitored",
                "pattern_keywords": ["CreateCustomerGateway", "DeleteCustomerGateway",
                                     "AttachInternetGateway", "CreateInternetGateway",
                                     "DeleteInternetGateway", "DetachInternetGateway"],
                "description": "Detects network gateway changes"
            },
            "4.13": {
                "title": "Route table changes monitored",
                "pattern_keywords": ["CreateRoute", "CreateRouteTable", "ReplaceRoute",
                                     "ReplaceRouteTableAssociation", "DeleteRouteTable",
                                     "DeleteRoute", "DisassociateRouteTable"],
                "description": "Detects route table changes"
            },
            "4.14": {
                "title": "VPC changes monitored",
                "pattern_keywords": ["CreateVpc", "DeleteVpc", "ModifyVpcAttribute",
                                     "AcceptVpcPeeringConnection", "CreateVpcPeeringConnection",
                                     "DeleteVpcPeeringConnection", "RejectVpcPeeringConnection",
                                     "AttachClassicLinkVpc", "DetachClassicLinkVpc",
                                     "DisableVpcClassicLink", "EnableVpcClassicLink"],
                "description": "Detects VPC changes"
            },
            "4.15": {
                "title": "AWS Organizations changes monitored",
                "pattern_keywords": ["AcceptHandshake", "AttachPolicy", "CreateAccount",
                                     "CreateOrganizationalUnit", "CreatePolicy", "DeclineHandshake",
                                     "DeleteOrganization", "DeleteOrganizationalUnit", "DeletePolicy",
                                     "DetachPolicy", "DisablePolicyType", "EnablePolicyType",
                                     "InviteAccountToOrganization", "LeaveOrganization",
                                     "RemoveAccountFromOrganization", "UpdateOrganizationalUnit",
                                     "UpdatePolicy"],
                "description": "Detects AWS Organizations changes"
            }
        }

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

    def pattern_matches(self, metric_filter_pattern: str, keywords: List[str]) -> bool:
        """
        Check if a metric filter pattern contains the expected keywords.
        This is a simplified check - actual patterns can be complex JSON patterns.
        """
        if not metric_filter_pattern:
            return False

        # Convert pattern to lowercase for case-insensitive matching
        pattern_lower = metric_filter_pattern.lower()

        # Check if pattern contains key indicators
        # For patterns with multiple keywords, we need at least some of them
        matches = sum(1 for keyword in keywords if keyword.lower() in pattern_lower)

        # If pattern has at least 2 of the keywords (or 1 for simple patterns), consider it a match
        threshold = min(2, len(keywords))
        return matches >= threshold

    def has_alarm_for_metric(self, metric_name: str, alarms: List[Dict]) -> bool:
        """Check if there's an active CloudWatch alarm for the given metric"""
        for alarm in alarms:
            # Check if alarm is for this metric
            for metric in alarm.get('Metrics', []):
                if metric.get('MetricStat', {}).get('Metric', {}).get('MetricName') == metric_name:
                    return True
            # Also check older alarm format
            if alarm.get('MetricName') == metric_name:
                return True
        return False

    def check_metric_filter_and_alarm(self, control: str):
        """Generic check for metric filter pattern and corresponding alarm"""
        pattern_info = self.required_patterns.get(control)
        if not pattern_info:
            return

        found_filter = False
        found_alarm = False

        # Check all regions for metric filters
        cloudwatch_data = self.data.get("cloudwatch", {})

        for region, region_data in cloudwatch_data.items():
            log_groups = region_data.get("log_groups", [])
            alarms = region_data.get("alarms", [])

            for lg_info in log_groups:
                metric_filters = lg_info.get("metric_filters", [])

                for mf in metric_filters:
                    pattern = mf.get("filterPattern", "")

                    # Check if this filter matches the required pattern
                    if self.pattern_matches(pattern, pattern_info["pattern_keywords"]):
                        found_filter = True

                        # Check if there's an alarm for this metric
                        metric_transformations = mf.get("metricTransformations", [])
                        for mt in metric_transformations:
                            metric_name = mt.get("metricName")
                            if metric_name and self.has_alarm_for_metric(metric_name, alarms):
                                found_alarm = True
                                break

                    if found_filter and found_alarm:
                        break
                if found_filter and found_alarm:
                    break
            if found_filter and found_alarm:
                break

        if found_filter and found_alarm:
            self.add_finding(
                control,
                pattern_info["title"],
                "PASS",
                f"{pattern_info['description']} - Metric filter and alarm configured",
                "LOW"
            )
        elif found_filter:
            self.add_finding(
                control,
                pattern_info["title"],
                "FAIL",
                f"{pattern_info['description']} - Metric filter exists but no alarm configured",
                "HIGH"
            )
        else:
            self.add_finding(
                control,
                pattern_info["title"],
                "FAIL",
                f"{pattern_info['description']} - No metric filter or alarm configured",
                "HIGH"
            )

    def check_4_16_security_hub(self):
        """CIS 4.16: Ensure AWS Security Hub is enabled"""
        # Note: Security Hub status is not collected by logging_collector
        # This would require a separate AWS Security Hub API call
        self.add_finding(
            "4.16",
            "AWS Security Hub enabled",
            "MANUAL",
            "Security Hub status requires manual verification or separate API call",
            "MEDIUM"
        )

    def analyze_all(self):
        """Run all monitoring compliance checks"""
        print("\nAnalyzing CloudWatch Monitoring compliance...")
        print("-" * 60)

        # Check controls 4.1 through 4.15 (metric filter + alarm checks)
        for control in ["4.1", "4.2", "4.3", "4.4", "4.5", "4.6", "4.7", "4.8",
                        "4.9", "4.10", "4.11", "4.12", "4.13", "4.14", "4.15"]:
            self.check_metric_filter_and_alarm(control)

        # Check 4.16 (Security Hub)
        self.check_4_16_security_hub()

        # Print summary
        passed = len([f for f in self.findings if f["status"] == "PASS"])
        failed = len([f for f in self.findings if f["status"] == "FAIL"])
        manual = len([f for f in self.findings if f["status"] == "MANUAL"])

        print(f"\nAnalysis complete! Total findings: {len(self.findings)}")
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

        # Sort by control number
        df = df.sort_values('control')

        # Save to CSV
        df.to_csv(filename, index=False)
        print(f"CSV report saved: {filename}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Analyze Monitoring data for CIS compliance")
    parser.add_argument("--input", required=True, help="Input data file from Logging collector")
    parser.add_argument("--output", default="monitoring_compliance_report.json", help="Output report file")

    args = parser.parse_args()

    analyzer = MonitoringAnalyzer(args.input)
    analyzer.analyze_all()
    analyzer.save_report(args.output)
