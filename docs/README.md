# AWS Review Documentation

Complete documentation for the AWS Security Review project based on CIS Amazon Web Services Foundations Benchmark v5.0.0.

## Getting Started Guides

These guides help you set up and use the AWS Review tool:

### [QUICKSTART.md](guides/QUICKSTART.md)
5-minute quick start guide. Get the tool running in minimal time.

**Use this when:** You want to get started quickly and run your first audit.

### [TESTING_GUIDE.md](guides/TESTING_GUIDE.md)
Comprehensive testing instructions with expected outputs and troubleshooting.

**Use this when:** You want to thoroughly test all components and understand what to expect.

### [TESTING_STEPS.txt](guides/TESTING_STEPS.txt)
Step-by-step testing checklist in plain text format.

**Use this when:** You prefer a simple checklist format for testing.

### [USAGE.md](guides/USAGE.md)
Complete usage guide covering all commands and options.

**Use this when:** You need detailed information about all available commands and features.

## Reference Documentation

Technical reference and troubleshooting resources:

### [AWS_PERMISSIONS_REQUIRED.md](reference/AWS_PERMISSIONS_REQUIRED.md)
Complete guide to AWS IAM permissions needed to run audits.

**Includes:**
- Quick setup with AWS managed policies (SecurityAudit + ViewOnlyAccess)
- Custom minimal permissions policy
- Permissions breakdown by section
- Troubleshooting permission errors

### [COMMON_ERRORS.md](reference/COMMON_ERRORS.md)
Troubleshooting guide for common errors and issues.

**Covers:**
- Profile name typos
- AccessDenied errors
- Missing dependencies
- Empty data collection
- Performance issues

### [QUICK_REFERENCE.md](reference/QUICK_REFERENCE.md)
Command cheat sheet and quick reference card.

**Includes:**
- Essential commands
- AWS CLI test commands
- Common scenarios
- Copy-paste commands

### [SECTIONS_OVERVIEW.md](reference/SECTIONS_OVERVIEW.md)
Complete breakdown of all 72 CIS controls across 8 sections.

**Shows:**
- All CIS control categories
- Implementation status
- Automation level for each control
- What's implemented and what's planned

### [GIT_WORKFLOW.md](reference/GIT_WORKFLOW.md)
Git commands and workflows for the project.

**Covers:**
- Common git commands
- Syncing with GitHub
- Branch management
- Troubleshooting git issues

## Project Documentation

Information about the project development and changes:

### [WHATS_NEW.md](WHATS_NEW.md)
Release notes and new features.

**Latest updates:**
- v1.1.0 - Added Storage Analyzer (9 checks)
- v1.1.0 - Added Logging Analyzer (8 checks)
- v1.1.0 - 30 total automated checks (up from 13)

### [FIXES_AND_IMPROVEMENTS.md](FIXES_AND_IMPROVEMENTS.md)
Development history and detailed roadmap.

**Includes:**
- Issues found and fixed
- Current coverage summary (30/72 controls = 42%)
- Future improvements roadmap
- Performance tips

### [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md)
High-level project overview and architecture.

**Covers:**
- Project goals
- Architecture overview
- Technology stack
- Design decisions

## Documentation Structure

```
docs/
├── README.md (this file)           # Documentation index
│
├── guides/                          # User guides
│   ├── QUICKSTART.md                # 5-minute setup
│   ├── TESTING_GUIDE.md             # Comprehensive testing
│   ├── TESTING_STEPS.txt            # Step-by-step checklist
│   └── USAGE.md                     # Complete usage guide
│
├── reference/                       # Reference documentation
│   ├── AWS_PERMISSIONS_REQUIRED.md  # AWS permissions guide
│   ├── COMMON_ERRORS.md             # Error troubleshooting
│   ├── QUICK_REFERENCE.md           # Command cheat sheet
│   ├── SECTIONS_OVERVIEW.md         # All 72 CIS controls
│   └── GIT_WORKFLOW.md              # Git commands
│
├── WHATS_NEW.md                     # Release notes
├── FIXES_AND_IMPROVEMENTS.md        # Development history
└── PROJECT_SUMMARY.md               # Project overview
```

## Common Use Cases

### I'm setting up for the first time
1. Read [QUICKSTART.md](guides/QUICKSTART.md)
2. Check [AWS_PERMISSIONS_REQUIRED.md](reference/AWS_PERMISSIONS_REQUIRED.md)
3. Run `python test_setup.py`
4. Run your first audit

### I got an error
1. Check [COMMON_ERRORS.md](reference/COMMON_ERRORS.md)
2. Look for your specific error message
3. Follow the fix instructions
4. If still stuck, check [TESTING_GUIDE.md](guides/TESTING_GUIDE.md)

### I want to understand all available commands
1. Read [USAGE.md](guides/USAGE.md) for detailed explanations
2. Use [QUICK_REFERENCE.md](reference/QUICK_REFERENCE.md) for quick lookups

### I want to know what's automated
1. Check [SECTIONS_OVERVIEW.md](reference/SECTIONS_OVERVIEW.md)
2. See which of the 72 CIS controls are implemented
3. Understand what's manual vs. automated

### I need to sync with GitHub
1. Read [GIT_WORKFLOW.md](reference/GIT_WORKFLOW.md)
2. Follow the quick commands section
3. Understand what files are git-ignored

### I want to understand recent changes
1. Read [WHATS_NEW.md](WHATS_NEW.md) for latest features
2. Check [FIXES_AND_IMPROVEMENTS.md](FIXES_AND_IMPROVEMENTS.md) for detailed history

## Quick Links

| I want to... | Read this |
|--------------|-----------|
| **Set up the tool** | [QUICKSTART.md](guides/QUICKSTART.md) |
| **Fix an error** | [COMMON_ERRORS.md](reference/COMMON_ERRORS.md) |
| **Find a command** | [QUICK_REFERENCE.md](reference/QUICK_REFERENCE.md) |
| **Add AWS permissions** | [AWS_PERMISSIONS_REQUIRED.md](reference/AWS_PERMISSIONS_REQUIRED.md) |
| **See all CIS controls** | [SECTIONS_OVERVIEW.md](reference/SECTIONS_OVERVIEW.md) |
| **Test the tool** | [TESTING_GUIDE.md](guides/TESTING_GUIDE.md) |
| **Sync with GitHub** | [GIT_WORKFLOW.md](reference/GIT_WORKFLOW.md) |
| **See what's new** | [WHATS_NEW.md](WHATS_NEW.md) |
| **Understand architecture** | [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md) |

## Contributing to Documentation

When adding new documentation:

1. **User Guides** go in `guides/` - Step-by-step instructions for users
2. **Reference docs** go in `reference/` - Technical reference and troubleshooting
3. **Project docs** stay in `docs/` root - Development and project information
4. Update this README.md to include the new document

## Need Help?

1. Check [COMMON_ERRORS.md](reference/COMMON_ERRORS.md) for troubleshooting
2. Review [TESTING_GUIDE.md](guides/TESTING_GUIDE.md) for comprehensive testing
3. See [QUICK_REFERENCE.md](reference/QUICK_REFERENCE.md) for command reference

---

**Main Project README:** [../README.md](../README.md)

**GitHub Repository:** https://github.com/chester74008/AWS_Review.git
