# Git Workflow - AWS Review Project

## Repository Information

**GitHub Repository:** https://github.com/chester74008/AWS_Review.git
**Branch:** main

---

## Quick Commands

### Check Status
```bash
git status
```

### Pull Latest Changes
```bash
git pull origin main
```

### Add and Commit Changes
```bash
# Add all changes
git add .

# Or add specific files
git add filename.py

# Commit with message
git commit -m "Description of changes"
```

### Push to GitHub
```bash
git push origin main
```

### View Commit History
```bash
git log --oneline -10
```

---

## Common Workflows

### Workflow 1: Daily Updates After Making Changes

```bash
# Check what changed
git status

# Add all changes
git add .

# Commit with descriptive message
git commit -m "Updated IAM analyzer with new checks"

# Push to GitHub
git push origin main
```

### Workflow 2: After Adding New Features

```bash
git add .
git commit -m "$(cat <<'EOF'
Added CloudWatch Monitoring Analyzer

- Implemented 15 metric filter checks
- Added alarm verification
- Updated documentation

🤖 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>
EOF
)"
git push origin main
```

### Workflow 3: Before Making Changes (Pull Latest)

```bash
# Get latest changes from GitHub
git pull origin main

# Make your changes
# Then add, commit, push as usual
```

---

## What Gets Committed (and What Doesn't)

### ✅ Files That ARE Committed:
- Python scripts (*.py)
- Documentation (*.md, *.txt)
- Configuration examples (config.example.json)
- Requirements (requirements.txt)
- CIS controls data (cis_aws_controls.json)
- Benchmark files (PDF, XLSX)

### ❌ Files That Are NOT Committed (.gitignore):
- Audit reports (reports/)
- Generated data files (*.json except specific ones)
- Python cache (__pycache__/)
- Virtual environments (venv/, env/)
- IDE settings (.vscode/, .idea/)
- Local config (config/config.json)
- Log files (*.log)

**Why?** Audit reports contain your AWS account data - keep them private!

---

## Important Notes

### Security Best Practices

1. **Never commit:**
   - AWS credentials
   - Access keys
   - Audit reports with account-specific data
   - Sensitive configuration files

2. **Always review before committing:**
   ```bash
   git status
   git diff
   ```

3. **Check what will be committed:**
   ```bash
   git status
   ```

4. **If you accidentally added sensitive data:**
   ```bash
   # Remove from staging
   git reset filename.json

   # Or remove from last commit (if not pushed yet)
   git reset --soft HEAD~1
   ```

---

## Syncing Multiple Computers

### On Computer A (where you made changes):
```bash
git add .
git commit -m "Your changes"
git push origin main
```

### On Computer B (getting the changes):
```bash
git pull origin main
```

---

## Branch Management (Optional)

### Create a New Branch for Development
```bash
git checkout -b feature/networking-analyzer
# Make changes
git add .
git commit -m "Working on networking analyzer"
git push origin feature/networking-analyzer
```

### Switch Back to Main
```bash
git checkout main
```

### Merge Feature Branch to Main
```bash
git checkout main
git merge feature/networking-analyzer
git push origin main
```

---

## Common Issues and Solutions

### Issue: "Updates were rejected"

**Cause:** Someone else pushed changes, or you made changes on another computer.

**Fix:**
```bash
git pull origin main
# Resolve any conflicts if needed
git push origin main
```

### Issue: Merge Conflicts

**Cause:** Same file edited in different ways.

**Fix:**
1. Open the conflicted file
2. Look for conflict markers:
   ```
   <<<<<<< HEAD
   Your changes
   =======
   Their changes
   >>>>>>> origin/main
   ```
3. Edit to keep the correct version
4. Remove conflict markers
5. Commit:
   ```bash
   git add .
   git commit -m "Resolved merge conflicts"
   git push origin main
   ```

### Issue: Want to Undo Last Commit (not pushed yet)

**Fix:**
```bash
# Keep changes, undo commit
git reset --soft HEAD~1

# Or discard changes and commit
git reset --hard HEAD~1
```

### Issue: Accidentally Committed Sensitive File

**If NOT pushed yet:**
```bash
git reset --soft HEAD~1
git reset HEAD sensitive-file.json
echo "sensitive-file.json" >> .gitignore
git add .
git commit -m "Remove sensitive file"
```

**If ALREADY pushed:**
Contact GitHub support or use git-filter-repo tool (advanced).

---

## Recommended Commit Message Format

### Simple Format
```bash
git commit -m "Brief description of changes"
```

### Detailed Format (Recommended)
```bash
git commit -m "$(cat <<'EOF'
Title: Brief summary (50 chars or less)

Detailed explanation:
- What changed
- Why it changed
- Any important notes

🤖 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>
EOF
)"
```

### Examples

**Good:**
```
Added Storage Analyzer

- Implemented 9 compliance checks for S3, RDS, EFS
- Added severity ratings
- Updated documentation
```

**Bad:**
```
Updates
Fixed stuff
asdf
```

---

## Viewing Your Repository on GitHub

**URL:** https://github.com/chester74008/AWS_Review

**What you'll see:**
- All your code and documentation
- Commit history
- File browser
- README.md displayed on homepage

---

## Cloning to Another Computer

```bash
git clone https://github.com/chester74008/AWS_Review.git
cd AWS_Review
pip install -r requirements.txt
```

---

## Quick Reference

| Task | Command |
|------|---------|
| Check status | `git status` |
| Add all files | `git add .` |
| Commit | `git commit -m "message"` |
| Push | `git push origin main` |
| Pull | `git pull origin main` |
| View history | `git log --oneline` |
| Undo last commit | `git reset --soft HEAD~1` |
| View changes | `git diff` |

---

## Automation Tips

### Create an Alias for Common Operations

**Windows PowerShell:**
```powershell
function gitpush {
    param($message)
    git add .
    git commit -m $message
    git push origin main
}

# Usage:
gitpush "Updated analyzers"
```

**Linux/Mac (.bashrc or .zshrc):**
```bash
gitpush() {
    git add .
    git commit -m "$1"
    git push origin main
}

# Usage:
gitpush "Updated analyzers"
```

---

## Repository Maintenance

### Keep README.md Updated

Update [README.md](README.md) when:
- Adding new features
- Changing usage instructions
- Updating requirements

### Tag Releases

When you complete major features:
```bash
git tag -a v1.0.0 -m "Initial release with 30 checks"
git push origin v1.0.0
```

### Check Repository Size

```bash
git count-objects -vH
```

If too large, consider removing large files or using Git LFS.

---

## Next Steps

1. **Verify on GitHub:** Visit https://github.com/chester74008/AWS_Review
2. **Clone to test:** Clone to another location to verify everything works
3. **Set up CI/CD (optional):** GitHub Actions for automated testing
4. **Enable branch protection (optional):** Require pull requests for main branch

---

**Your project is now on GitHub!** 🎉

All code and documentation is backed up and accessible from anywhere.
