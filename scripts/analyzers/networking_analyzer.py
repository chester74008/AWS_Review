#!/usr/bin/env python3
"""
Networking Compliance Analyzer for CIS AWS Benchmark
Analyzes VPC, Security Groups, NACLs, Route Tables, and EC2 metadata configuration
"""

import json
import pandas as pd
from datetime import datetime
from typing import Dict, List, Any


class NetworkingAnalyzer:
    """Analyzes Networking data for CIS compliance"""

    def __init__(self, data_file: str):
        with open(data_file, 'r') as f:
            self.data = json.load(f)
        self.findings = []

        # Remote server administration ports
        self.admin_ports = [22, 3389]  # SSH, RDP

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

    def check_5_1_1_ebs_encryption_default(self):
        """CIS 5.1.1: Ensure EBS volume encryption is enabled in all regions"""
        ebs_encryption_data = self.data.get("ebs_encryption_default", {})

        regions_without_encryption = []
        regions_with_encryption = []

        for region, encryption_status in ebs_encryption_data.items():
            enabled = encryption_status.get("EbsEncryptionByDefault", False)

            if not enabled:
                regions_without_encryption.append(region)
            else:
                regions_with_encryption.append(region)

        if regions_without_encryption:
            self.add_finding(
                "5.1.1",
                "EBS encryption by default not enabled in all regions",
                "FAIL",
                f"EBS encryption by default is disabled in {len(regions_without_encryption)} region(s): {', '.join(regions_without_encryption[:5])}{'...' if len(regions_without_encryption) > 5 else ''}",
                "HIGH"
            )
        else:
            self.add_finding(
                "5.1.1",
                "EBS encryption by default enabled in all regions",
                "PASS",
                f"EBS encryption by default is enabled in all {len(regions_with_encryption)} region(s)",
                "LOW"
            )

    def check_5_1_2_cifs_access(self):
        """CIS 5.1.2: Ensure CIFS access is restricted to trusted networks"""
        # CIFS uses port 445
        cifs_port = 445

        security_groups_data = self.data.get("security_groups", {})
        unrestricted_groups = []

        for region, security_groups in security_groups_data.items():
            for sg in security_groups:
                sg_id = sg.get("GroupId")
                sg_name = sg.get("GroupName")

                for permission in sg.get("IpPermissions", []):
                    from_port = permission.get("FromPort")
                    to_port = permission.get("ToPort")

                    # Check if rule allows CIFS port
                    if from_port is not None and to_port is not None:
                        if from_port <= cifs_port <= to_port:
                            # Check if it's open to 0.0.0.0/0
                            for ip_range in permission.get("IpRanges", []):
                                if ip_range.get("CidrIp") == "0.0.0.0/0":
                                    unrestricted_groups.append(f"{region}/{sg_id} ({sg_name})")

        if unrestricted_groups:
            self.add_finding(
                "5.1.2",
                "CIFS access not restricted to trusted networks",
                "FAIL",
                f"Found {len(unrestricted_groups)} security group(s) allowing CIFS (port 445) from 0.0.0.0/0: {', '.join(unrestricted_groups[:3])}{'...' if len(unrestricted_groups) > 3 else ''}",
                "HIGH"
            )
        else:
            self.add_finding(
                "5.1.2",
                "CIFS access restricted",
                "PASS",
                "No security groups allow CIFS (port 445) from 0.0.0.0/0",
                "LOW"
            )

    def check_5_2_nacl_admin_ports(self):
        """CIS 5.2: Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports"""
        network_acls_data = self.data.get("network_acls", {})
        vulnerable_nacls = []

        for region, network_acls in network_acls_data.items():
            for nacl in network_acls:
                nacl_id = nacl.get("NetworkAclId")

                for entry in nacl.get("Entries", []):
                    # Only check ingress rules
                    if not entry.get("Egress", True):
                        # Check if rule allows traffic (not deny)
                        if entry.get("RuleAction") == "allow":
                            cidr = entry.get("CidrBlock", "")
                            port_range = entry.get("PortRange", {})
                            from_port = port_range.get("From")
                            to_port = port_range.get("To")

                            # Check if it's from 0.0.0.0/0
                            if cidr == "0.0.0.0/0":
                                # Check if it allows admin ports
                                if from_port is not None and to_port is not None:
                                    for admin_port in self.admin_ports:
                                        if from_port <= admin_port <= to_port:
                                            vulnerable_nacls.append(f"{region}/{nacl_id} (port {admin_port})")
                                            break

        if vulnerable_nacls:
            self.add_finding(
                "5.2",
                "Network ACLs allow ingress from 0.0.0.0/0 to admin ports",
                "FAIL",
                f"Found {len(vulnerable_nacls)} NACL(s) allowing admin port access from 0.0.0.0/0: {', '.join(vulnerable_nacls[:3])}{'...' if len(vulnerable_nacls) > 3 else ''}",
                "CRITICAL"
            )
        else:
            self.add_finding(
                "5.2",
                "No NACLs allow ingress from 0.0.0.0/0 to admin ports",
                "PASS",
                "Network ACLs properly restrict admin port access",
                "LOW"
            )

    def check_5_3_security_groups_ipv4_admin_ports(self):
        """CIS 5.3: Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports"""
        security_groups_data = self.data.get("security_groups", {})
        vulnerable_groups = []

        for region, security_groups in security_groups_data.items():
            for sg in security_groups:
                sg_id = sg.get("GroupId")
                sg_name = sg.get("GroupName")

                for permission in sg.get("IpPermissions", []):
                    from_port = permission.get("FromPort")
                    to_port = permission.get("ToPort")

                    if from_port is not None and to_port is not None:
                        # Check if rule allows admin ports
                        for admin_port in self.admin_ports:
                            if from_port <= admin_port <= to_port:
                                # Check if it's open to 0.0.0.0/0
                                for ip_range in permission.get("IpRanges", []):
                                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                                        vulnerable_groups.append(f"{region}/{sg_id} ({sg_name}) port {admin_port}")

        if vulnerable_groups:
            self.add_finding(
                "5.3",
                "Security groups allow ingress from 0.0.0.0/0 to admin ports",
                "FAIL",
                f"Found {len(vulnerable_groups)} security group(s) allowing admin port access from 0.0.0.0/0: {', '.join(vulnerable_groups[:3])}{'...' if len(vulnerable_groups) > 3 else ''}",
                "CRITICAL"
            )
        else:
            self.add_finding(
                "5.3",
                "No security groups allow ingress from 0.0.0.0/0 to admin ports",
                "PASS",
                "Security groups properly restrict admin port access from 0.0.0.0/0",
                "LOW"
            )

    def check_5_4_security_groups_ipv6_admin_ports(self):
        """CIS 5.4: Ensure no security groups allow ingress from ::/0 to remote server administration ports"""
        security_groups_data = self.data.get("security_groups", {})
        vulnerable_groups = []

        for region, security_groups in security_groups_data.items():
            for sg in security_groups:
                sg_id = sg.get("GroupId")
                sg_name = sg.get("GroupName")

                for permission in sg.get("IpPermissions", []):
                    from_port = permission.get("FromPort")
                    to_port = permission.get("ToPort")

                    if from_port is not None and to_port is not None:
                        # Check if rule allows admin ports
                        for admin_port in self.admin_ports:
                            if from_port <= admin_port <= to_port:
                                # Check if it's open to ::/0 (IPv6)
                                for ipv6_range in permission.get("Ipv6Ranges", []):
                                    if ipv6_range.get("CidrIpv6") == "::/0":
                                        vulnerable_groups.append(f"{region}/{sg_id} ({sg_name}) port {admin_port}")

        if vulnerable_groups:
            self.add_finding(
                "5.4",
                "Security groups allow ingress from ::/0 to admin ports",
                "FAIL",
                f"Found {len(vulnerable_groups)} security group(s) allowing admin port access from ::/0 (IPv6): {', '.join(vulnerable_groups[:3])}{'...' if len(vulnerable_groups) > 3 else ''}",
                "CRITICAL"
            )
        else:
            self.add_finding(
                "5.4",
                "No security groups allow ingress from ::/0 to admin ports",
                "PASS",
                "Security groups properly restrict admin port access from ::/0 (IPv6)",
                "LOW"
            )

    def check_5_5_default_security_group(self):
        """CIS 5.5: Ensure the default security group of every VPC restricts all traffic"""
        security_groups_data = self.data.get("security_groups", {})
        unrestricted_default_sgs = []

        for region, security_groups in security_groups_data.items():
            for sg in security_groups:
                sg_name = sg.get("GroupName")
                sg_id = sg.get("GroupId")

                # Check if this is a default security group
                if sg_name == "default":
                    has_inbound_rules = len(sg.get("IpPermissions", [])) > 0
                    has_outbound_rules = len(sg.get("IpPermissionsEgress", [])) > 0

                    # Default SG should have no rules
                    if has_inbound_rules or has_outbound_rules:
                        unrestricted_default_sgs.append(f"{region}/{sg_id}")

        if unrestricted_default_sgs:
            self.add_finding(
                "5.5",
                "Default security groups do not restrict all traffic",
                "FAIL",
                f"Found {len(unrestricted_default_sgs)} default security group(s) with active rules: {', '.join(unrestricted_default_sgs[:5])}{'...' if len(unrestricted_default_sgs) > 5 else ''}",
                "MEDIUM"
            )
        else:
            self.add_finding(
                "5.5",
                "Default security groups restrict all traffic",
                "PASS",
                "All default security groups have no inbound or outbound rules",
                "LOW"
            )

    def check_5_6_vpc_peering_routing(self):
        """CIS 5.6: Ensure routing tables for VPC peering are 'least access'"""
        route_tables_data = self.data.get("route_tables", {})
        overly_permissive_routes = []

        for region, route_tables in route_tables_data.items():
            for rt in route_tables:
                rt_id = rt.get("RouteTableId")

                for route in rt.get("Routes", []):
                    # Check if route is for VPC peering
                    if route.get("VpcPeeringConnectionId"):
                        dest_cidr = route.get("DestinationCidrBlock", "")

                        # Check if route is overly permissive (0.0.0.0/0 or very large CIDR blocks)
                        if dest_cidr in ["0.0.0.0/0", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]:
                            overly_permissive_routes.append(f"{region}/{rt_id} -> {dest_cidr}")

        if overly_permissive_routes:
            self.add_finding(
                "5.6",
                "VPC peering routing tables are overly permissive",
                "FAIL",
                f"Found {len(overly_permissive_routes)} overly permissive VPC peering route(s): {', '.join(overly_permissive_routes[:3])}{'...' if len(overly_permissive_routes) > 3 else ''}",
                "MEDIUM"
            )
        else:
            self.add_finding(
                "5.6",
                "VPC peering routing tables follow least access principle",
                "PASS",
                "No overly permissive VPC peering routes found",
                "LOW"
            )

    def check_5_7_ec2_metadata_imdsv2(self):
        """CIS 5.7: Ensure that the EC2 Metadata Service only allows IMDSv2"""
        ec2_instances_data = self.data.get("ec2_instances", {})
        instances_without_imdsv2 = []

        for region, instances in ec2_instances_data.items():
            for instance in instances:
                instance_id = instance.get("InstanceId")
                state = instance.get("State", {}).get("Name")

                # Only check running instances
                if state == "running":
                    metadata_options = instance.get("MetadataOptions", {})
                    http_tokens = metadata_options.get("HttpTokens", "optional")

                    # IMDSv2 requires HttpTokens to be "required"
                    if http_tokens != "required":
                        instances_without_imdsv2.append(f"{region}/{instance_id}")

        if instances_without_imdsv2:
            self.add_finding(
                "5.7",
                "EC2 instances do not enforce IMDSv2",
                "FAIL",
                f"Found {len(instances_without_imdsv2)} running instance(s) not enforcing IMDSv2: {', '.join(instances_without_imdsv2[:5])}{'...' if len(instances_without_imdsv2) > 5 else ''}",
                "HIGH"
            )
        else:
            total_instances = sum(len(instances) for instances in ec2_instances_data.values())
            if total_instances > 0:
                self.add_finding(
                    "5.7",
                    "EC2 instances enforce IMDSv2",
                    "PASS",
                    f"All running EC2 instances enforce IMDSv2",
                    "LOW"
                )
            else:
                self.add_finding(
                    "5.7",
                    "No EC2 instances to check",
                    "PASS",
                    "No running EC2 instances found",
                    "LOW"
                )

    def analyze_all(self):
        """Run all networking compliance checks"""
        print("\nAnalyzing Networking compliance...")
        print("-" * 60)

        self.check_5_1_1_ebs_encryption_default()
        self.check_5_1_2_cifs_access()
        self.check_5_2_nacl_admin_ports()
        self.check_5_3_security_groups_ipv4_admin_ports()
        self.check_5_4_security_groups_ipv6_admin_ports()
        self.check_5_5_default_security_group()
        self.check_5_6_vpc_peering_routing()
        self.check_5_7_ec2_metadata_imdsv2()

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

    parser = argparse.ArgumentParser(description="Analyze Networking data for CIS compliance")
    parser.add_argument("--input", required=True, help="Input data file from Networking collector")
    parser.add_argument("--output", default="networking_compliance_report.json", help="Output report file")

    args = parser.parse_args()

    analyzer = NetworkingAnalyzer(args.input)
    analyzer.analyze_all()
    analyzer.save_report(args.output)
