#!/bin/bash
# ─────────────────────────────────────────────────────────────
#  GitHub Repository Setup – Tenable SC Fixed Trend Builder
#  Run this script once from inside the Fixed_Trend_Builder folder
#  Usage:  bash github_setup.sh <your-github-username>
# ─────────────────────────────────────────────────────────────

GITHUB_USER=${1:-"YOUR_GITHUB_USERNAME"}
REPO_NAME="tenable-sc-fixed-trend"

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║  Tenable SC Fixed Trend – GitHub Setup       ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# Initialize git repo
git init
git add .
git commit -m "Initial commit: Tenable SC Fixed Vulnerability Trend Builder

- sc_trend.py       : CLI script (Hebrew UI)
- sc_trend_en.py    : CLI script (English UI)
- report_builder.py : Web UI server (Hebrew)
- report_builder_en.py : Web UI server (English)
- sc_debug.py / sc_debug2.py : Diagnostic tools
- README.md         : Full documentation"

echo ""
echo "✅ Local git repo initialized."
echo ""
echo "Next steps:"
echo ""
echo "  1. Go to: https://github.com/new"
echo "  2. Repository name: $REPO_NAME"
echo "  3. Set to: Public"
echo "  4. Do NOT initialize with README (you already have one)"
echo "  5. Click 'Create repository'"
echo "  6. Run these commands:"
echo ""
echo "     git remote add origin https://github.com/$GITHUB_USER/$REPO_NAME.git"
echo "     git branch -M main"
echo "     git push -u origin main"
echo ""
echo "  7. Copy your repo URL:"
echo "     https://github.com/$GITHUB_USER/$REPO_NAME"
echo ""
echo "  8. Go to: https://exchange-staging.tenable.com"
echo "     Log in with Okta → Submit Pull Request with your repo URL"
echo ""
