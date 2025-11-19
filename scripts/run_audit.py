#!/usr/bin/env python3
"""
Main CIS AWS Benchmark Audit Runner
Orchestrates data collection and compliance analysis
"""

import argparse
import sys
import os
from datetime import datetime

# Add collectors and analyzers to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'collectors'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'analyzers'))

from iam_collector import IAMCollector
from storage_collector import StorageCollector
from logging_collector import LoggingCollector
from iam_analyzer import IAMAnalyzer
from storage_analyzer import StorageAnalyzer
from logging_analyzer import LoggingAnalyzer


def print_banner():
    """Print audit banner"""
    print("="*80)
    print("CIS AWS FOUNDATIONS BENCHMARK v5.0.0 - AUTOMATED AUDIT")
    print("="*80)
    print(f"Audit started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()


def run_iam_audit(profile: str, region: str, output_dir: str):
    """Run IAM security audit"""
    print("\n" + "="*80)
    print("SECTION 1: IDENTITY AND ACCESS MANAGEMENT (IAM)")
    print("="*80)

    # Collect data
    data_file = os.path.join(output_dir, "iam_data.json")
    collector = IAMCollector(profile=profile, region=region)
    collector.collect_all()
    collector.save_to_file(data_file)

    # Analyze compliance
    print("\n" + "-"*80)
    report_file = os.path.join(output_dir, "iam_compliance_report.json")
    analyzer = IAMAnalyzer(data_file)
    analyzer.analyze_all()
    analyzer.save_report(report_file)

    return analyzer.findings


def run_storage_audit(profile: str, region: str, output_dir: str, all_regions: bool = False):
    """Run Storage security audit (S3, RDS, EFS)"""
    print("\n" + "="*80)
    print("SECTION 2: STORAGE (S3, RDS, EFS)")
    print("="*80)

    # Collect data
    data_file = os.path.join(output_dir, "storage_data.json")
    collector = StorageCollector(profile=profile, region=region)
    collector.collect_all(all_regions=all_regions)
    collector.save_to_file(data_file)

    # Analyze compliance
    print("\n" + "-"*80)
    report_file = os.path.join(output_dir, "storage_compliance_report.json")
    analyzer = StorageAnalyzer(data_file)
    analyzer.analyze_all()
    analyzer.save_report(report_file)

    return analyzer.findings


def run_logging_audit(profile: str, region: str, output_dir: str, all_regions: bool = False):
    """Run Logging and Monitoring audit"""
    print("\n" + "="*80)
    print("SECTION 3 & 4: LOGGING AND MONITORING")
    print("="*80)

    # Collect data
    data_file = os.path.join(output_dir, "logging_data.json")
    collector = LoggingCollector(profile=profile, region=region)
    collector.collect_all(all_regions=all_regions)
    collector.save_to_file(data_file)

    # Analyze compliance
    print("\n" + "-"*80)
    report_file = os.path.join(output_dir, "logging_compliance_report.json")
    analyzer = LoggingAnalyzer(data_file)
    analyzer.analyze_all()
    analyzer.save_report(report_file)

    return analyzer.findings


def generate_consolidated_csv(all_findings: dict, output_dir: str):
    """Generate a consolidated CSV file with all findings from all sections"""
    import pandas as pd

    # Combine all findings with section identifier
    all_records = []
    for section, findings in all_findings.items():
        for finding in findings:
            record = finding.copy()
            record['section'] = section
            all_records.append(record)

    if not all_records:
        return

    # Create DataFrame
    df = pd.DataFrame(all_records)

    # Reorder columns for better readability
    columns = ['section', 'control', 'title', 'status', 'severity', 'details', 'timestamp']
    df = df[columns]

    # Sort by section and control number
    df = df.sort_values(['section', 'control'])

    # Save consolidated CSV
    csv_file = os.path.join(output_dir, "audit_all_findings.csv")
    df.to_csv(csv_file, index=False)
    print(f"\nConsolidated CSV report saved: {csv_file}")

    # Also create a failures-only CSV for quick action
    failures_df = df[df['status'] == 'FAIL'].copy()
    if not failures_df.empty:
        # Sort failures by severity (CRITICAL > HIGH > MEDIUM > LOW)
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        failures_df['severity_rank'] = failures_df['severity'].map(severity_order)
        failures_df = failures_df.sort_values(['severity_rank', 'section', 'control'])
        failures_df = failures_df.drop('severity_rank', axis=1)

        failures_file = os.path.join(output_dir, "audit_failures_only.csv")
        failures_df.to_csv(failures_file, index=False)
        print(f"Failures-only CSV saved: {failures_file}")


def generate_summary_report(all_findings: dict, output_dir: str):
    """Generate a summary report of all findings"""
    import json

    summary = {
        "audit_time": datetime.now().isoformat(),
        "total_findings": sum(len(findings) for findings in all_findings.values()),
        "by_section": {}
    }

    for section, findings in all_findings.items():
        passed = len([f for f in findings if f["status"] == "PASS"])
        failed = len([f for f in findings if f["status"] == "FAIL"])
        manual = len([f for f in findings if f["status"] == "MANUAL"])

        summary["by_section"][section] = {
            "total": len(findings),
            "passed": passed,
            "failed": failed,
            "manual": manual,
            "compliance_percentage": round((passed / len(findings) * 100) if findings else 0, 2)
        }

    # Overall compliance
    total_checks = summary["total_findings"]
    total_passed = sum(s["passed"] for s in summary["by_section"].values())
    summary["overall_compliance_percentage"] = round((total_passed / total_checks * 100) if total_checks else 0, 2)

    # Save summary JSON
    summary_file = os.path.join(output_dir, "audit_summary.json")
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)

    # Create consolidated CSV with all findings
    generate_consolidated_csv(all_findings, output_dir)

    # Print summary to console
    print("\n" + "="*80)
    print("AUDIT SUMMARY")
    print("="*80)
    print(f"Overall Compliance: {summary['overall_compliance_percentage']}%")
    print(f"Total Checks: {total_checks}")
    print()

    for section, stats in summary["by_section"].items():
        print(f"{section}:")
        print(f"  Compliance: {stats['compliance_percentage']}%")
        print(f"  Passed: {stats['passed']}/{stats['total']}")
        print(f"  Failed: {stats['failed']}")
        print(f"  Manual: {stats['manual']}")
        print()

    print(f"Detailed reports saved to: {output_dir}")
    print(f"Summary report: {summary_file}")


def main():
    parser = argparse.ArgumentParser(
        description="CIS AWS Foundations Benchmark Automated Audit Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run full audit with default profile
  python run_audit.py --profile default

  # Run only IAM checks
  python run_audit.py --category iam --profile myprofile

  # Run audit across all regions
  python run_audit.py --all-regions --profile production

  # Run Level 1 checks only
  python run_audit.py --level 1 --profile default
        """
    )

    parser.add_argument("--profile", default="default", help="AWS profile to use (default: default)")
    parser.add_argument("--region", default="us-east-1", help="Primary AWS region (default: us-east-1)")
    parser.add_argument("--category", choices=["iam", "storage", "logging", "all"], default="all",
                        help="Category to audit (default: all)")
    parser.add_argument("--level", type=int, choices=[1, 2], help="CIS Level to audit (1 or 2)")
    parser.add_argument("--all-regions", action="store_true", help="Collect data from all AWS regions")
    parser.add_argument("--output-dir", default="reports", help="Output directory for reports")

    args = parser.parse_args()

    # Create output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.join(args.output_dir, f"audit_{timestamp}")
    os.makedirs(output_dir, exist_ok=True)

    print_banner()
    print(f"AWS Profile: {args.profile}")
    print(f"Primary Region: {args.region}")
    print(f"All Regions: {args.all_regions}")
    print(f"Category: {args.category}")
    if args.level:
        print(f"CIS Level: {args.level}")
    print(f"Output Directory: {output_dir}")
    print()

    all_findings = {}

    try:
        # Run requested audits
        if args.category in ["iam", "all"]:
            findings = run_iam_audit(args.profile, args.region, output_dir)
            all_findings["IAM"] = findings

        if args.category in ["storage", "all"]:
            findings = run_storage_audit(args.profile, args.region, output_dir, args.all_regions)
            all_findings["Storage"] = findings

        if args.category in ["logging", "all"]:
            findings = run_logging_audit(args.profile, args.region, output_dir, args.all_regions)
            all_findings["Logging"] = findings

        # Generate summary
        if all_findings:
            generate_summary_report(all_findings, output_dir)

    except KeyboardInterrupt:
        print("\n\nAudit interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nError during audit: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)

    print("\n" + "="*80)
    print("AUDIT COMPLETE")
    print("="*80)


if __name__ == "__main__":
    main()
