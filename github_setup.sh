#!/bin/bash
# ─────────────────────────────────────────────────────────────
#  GitHub Repository Setup – Tenable SC Fixed Trend Builder
#  Run once from inside the Fixed_Trend_Builder folder:
#  bash github_setup.sh <your-github-username>
# ─────────────────────────────────────────────────────────────

GITHUB_USER=${1:-"YOUR_GITHUB_USERNAME"}
REPO_NAME="tenable-sc-fixed-trend"

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║  Tenable SC Fixed Trend – GitHub Setup       ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

git init
git add .
git commit -m "Initial commit: Tenable SC Fixed Vulnerability Trend Builder"

echo ""
echo "Next steps:"
echo ""
echo "  1. Go to: https://github.com/new"
echo "  2. Repository name: $REPO_NAME"
echo "  3. Visibility: Public"
echo "  4. Do NOT initialize with README"
echo "  5. Click 'Create repository', then run:"
echo ""
echo "     git remote add origin https://github.com/$GITHUB_USER/$REPO_NAME.git"
echo "     git branch -M main"
echo "     git push -u origin main"
echo ""
echo "  6. Submit to the Cyber Agents Exchange:"
echo "     https://exchange-staging.tenable.com"
echo "     Repo URL: https://github.com/$GITHUB_USER/$REPO_NAME"
echo ""
