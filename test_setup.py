#!/usr/bin/env python3
"""
Setup verification script for AWS Review project
Run this to verify your environment is ready for testing
"""

import sys
import subprocess
import os

def print_header(text):
    print("\n" + "="*60)
    print(f"  {text}")
    print("="*60)

def print_status(check, status, message=""):
    symbols = {"pass": "OK", "fail": "FAIL", "warn": "WARN"}

    symbol = symbols.get(status, "?")
    print(f"[{symbol}] {check}: {message}")
    return status == "pass"

def check_python():
    """Check Python version"""
    version = sys.version_info
    if version.major == 3 and version.minor >= 8:
        return print_status(
            "Python Version",
            "pass",
            f"Python {version.major}.{version.minor}.{version.micro}"
        )
    else:
        return print_status(
            "Python Version",
            "fail",
            f"Python {version.major}.{version.minor}.{version.micro} (need 3.8+)"
        )

def check_aws_cli():
    """Check if AWS CLI is installed"""
    try:
        result = subprocess.run(
            ["aws", "--version"],
            capture_output=True,
            text=True,
            check=False
        )
        if result.returncode == 0:
            version = result.stdout.strip() or result.stderr.strip()
            return print_status("AWS CLI Installed", "pass", version)
        else:
            return print_status("AWS CLI Installed", "fail", "Not found")
    except FileNotFoundError:
        return print_status(
            "AWS CLI Installed",
            "fail",
            "Install from: https://aws.amazon.com/cli/"
        )

def check_aws_credentials():
    """Check if AWS credentials are configured"""
    try:
        result = subprocess.run(
            ["aws", "sts", "get-caller-identity"],
            capture_output=True,
            text=True,
            check=False
        )
        if result.returncode == 0:
            import json
            identity = json.loads(result.stdout)
            account = identity.get("Account", "Unknown")
            user = identity.get("Arn", "Unknown").split("/")[-1]
            return print_status(
                "AWS Credentials",
                "pass",
                f"Account: {account}, User: {user}"
            )
        else:
            return print_status(
                "AWS Credentials",
                "fail",
                "Run 'aws configure' to set up credentials"
            )
    except FileNotFoundError:
        return print_status("AWS Credentials", "fail", "AWS CLI not installed")
    except Exception as e:
        return print_status("AWS Credentials", "fail", str(e))

def check_dependencies():
    """Check if required Python packages are installed"""
    required = ["pandas", "openpyxl"]
    all_installed = True

    for package in required:
        try:
            __import__(package)
            print_status(f"Package: {package}", "pass", "Installed")
        except ImportError:
            print_status(f"Package: {package}", "fail", "Not installed")
            all_installed = False

    if not all_installed:
        print("\n  → Run: pip install -r requirements.txt")

    return all_installed

def check_project_structure():
    """Check if project files exist"""
    required_files = [
        "scripts/collectors/iam_collector.py",
        "scripts/analyzers/iam_analyzer.py",
        "scripts/run_audit.py",
        "requirements.txt",
        "cis_aws_controls.json"
    ]

    all_exist = True
    for file_path in required_files:
        if os.path.exists(file_path):
            print_status(f"File: {file_path}", "pass", "Found")
        else:
            print_status(f"File: {file_path}", "fail", "Missing")
            all_exist = False

    return all_exist

def check_aws_permissions():
    """Test basic AWS read permissions"""
    try:
        result = subprocess.run(
            ["aws", "iam", "list-users", "--max-items", "1"],
            capture_output=True,
            text=True,
            check=False
        )
        if result.returncode == 0:
            return print_status(
                "AWS IAM Read Permission",
                "pass",
                "Can read IAM data"
            )
        elif "AccessDenied" in result.stderr:
            return print_status(
                "AWS IAM Read Permission",
                "fail",
                "Need ReadOnlyAccess or IAM read permissions"
            )
        else:
            return print_status(
                "AWS IAM Read Permission",
                "warn",
                result.stderr[:100]
            )
    except Exception as e:
        return print_status("AWS IAM Read Permission", "fail", str(e))

def main():
    print_header("AWS Review Project - Setup Verification")

    results = []

    # Check Python
    print_header("1. Python Environment")
    results.append(check_python())
    results.append(check_dependencies())

    # Check AWS CLI
    print_header("2. AWS CLI Setup")
    results.append(check_aws_cli())
    results.append(check_aws_credentials())
    results.append(check_aws_permissions())

    # Check project structure
    print_header("3. Project Files")
    results.append(check_project_structure())

    # Summary
    print_header("Setup Summary")
    passed = sum(results)
    total = len(results)

    print(f"\nPassed: {passed}/{total} checks")

    if all(results):
        print("\n[OK] All checks passed! You're ready to run audits.")
        print("\nNext steps:")
        print("  1. Run a test: python scripts/collectors/iam_collector.py --profile default --output test.json")
        print("  2. See TESTING_GUIDE.md for detailed testing instructions")
        print("  3. Run full audit: python scripts/run_audit.py --category iam --profile default")
        return 0
    else:
        print("\n[FAIL] Some checks failed. Please fix the issues above.")
        print("\nCommon fixes:")
        print("  - Install AWS CLI: https://aws.amazon.com/cli/")
        print("  - Configure credentials: aws configure")
        print("  - Install dependencies: pip install -r requirements.txt")
        print("\nSee TESTING_GUIDE.md for detailed setup instructions")
        return 1

if __name__ == "__main__":
    sys.exit(main())
