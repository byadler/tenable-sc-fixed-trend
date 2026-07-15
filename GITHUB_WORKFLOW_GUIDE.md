# GitHub Workflow Guide – Building & Sharing Skills
## Tenable Cyber Agents Exchange | Internal SE Program

---

## Overview

Two parallel tracks for sharing work:

| Track | Platform | Purpose |
|-------|----------|---------|
| **Cyber Agents Exchange** | GitHub (public) | Share tools with customers & community |
| **ACE Factory / Ideas Portal** | Joel's internal portal | Coordinate SE skills for Cowork rollout |

---

## Track 1 — Cyber Agents Exchange (GitHub)

### What gets submitted
- **Skills** — Python scripts, CLI tools, automation workflows (like sc_trend.py)
- **Agents** — AI agents that automate multi-step security tasks
- **MCP Servers** — Model Context Protocol servers
- **Playbooks** — Workflows that chain multiple agents together

### Key principle
Your **code stays in your own GitHub repo**. The exchange only stores a small **metadata file** (listing) that points to your repo.

---

### Full Workflow — Step by Step

#### Part A: Publish your code (your own repo)

```bash
# 1. Initialize git in your project folder
cd /path/to/your/project
git init
git add .
git commit -m "Initial commit: [Project Name]"

# 2. Create repo on github.com/new (Public, no README)
# Then connect and push:
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git branch -M main
git push -u origin main

# 3. Future updates:
git add .
git commit -m "Description of changes"
git push
```

#### Part B: Submit listing to the exchange

```bash
# 1. Fork the exchange repo (once, via GitHub web)
# Go to: github.com/tenable-cyberagents-exchange/exchange-founders-prelaunch-agents
# Click Fork → Create fork

# 2. Clone YOUR fork
git clone https://YOUR_USERNAME:YOUR_TOKEN@github.com/YOUR_USERNAME/exchange-founders-prelaunch-agents.git
cd exchange-founders-prelaunch-agents

# 3. Create a branch
git checkout -b add-YOUR_USERNAME-your-skill-name

# 4. Copy the right template
cp templates/skill-template.md skills/YOUR_USERNAME-your-skill-name.md
# (or agents/, mcp-servers/, playbooks/ depending on type)

# 5. Edit the listing file (see template section below)
# 6. Commit and push
git add .
git commit -m "Add [skill name] by YOUR_USERNAME"
git push origin add-YOUR_USERNAME-your-skill-name

# 7. Open Pull Request on GitHub
# GitHub will show a banner: "Compare & pull request" — click it
```

> **Shortcut (no terminal):** GitHub web UI → Fork → navigate to skills/ → Add file → Upload files → Create new branch → Propose changes → Create PR

---

### Listing File Template (skill-template.md)

```markdown
---
name: "Your Skill Name"
author: "your-github-username"
github_url: "https://github.com/your-username/your-repo"
description: "A one-line description of what your skill does."
license: "MIT"
tier: "unreviewed"
tags: ["tag1", "tag2"]
integrations: ["Tenable Security Center"]
date_added: 2026-01-01
compatible_platforms: ["Claude Code", "Python 3.6+"]
invocation: "py your_script.py"
---

One paragraph: what problem does this solve and why does it matter?

## What it does
- Bullet 1
- Bullet 2

## How it works
Brief technical overview.

## Requirements
- Python 3.6+
- No pip installs required
```

---

### Trust Tiers (progression over time)

| Tier | Meaning |
|------|---------|
| `unreviewed` | All submissions start here — DJ/Justin do a basic review |
| `community-reviewed` | Used and tested by community members |
| `certified` | Tested by Tenable's product security team (Amanda & Blake) |

---

### GitHub Setup Requirements

| Item | Details |
|------|---------|
| GitHub account | Personal account (e.g. byadler) |
| Org access | Request from DJ Zito or Justin Buchanan via Slack |
| Authentication | Personal Access Token (PAT) — github.com → Settings → Developer Settings → Tokens (classic) → scope: `repo` |
| Invitation | Accept GitHub org invite via github.com/notifications |

---

### Leaderboard & Recognition

- Every PR gets a sequential number — **low numbers = Founding Contributor status**
- Stars on your GitHub repo = ranking on the exchange leaderboard
- Ask teammates to star your repo: `https://github.com/YOUR_USERNAME/YOUR_REPO`
- Founding contributors get special swag

---

## Track 2 — ACE Factory / Ideas Portal (Internal)

### Purpose
Coordinate SE skills for the Claude Cowork rollout — prevent duplicate work across the global SE team.

### Rules
- **Check before building** — search the portal first to see if someone is already working on the same idea
- **Post even rough ideas** — someone else might build it
- **2-3 SEs can collaborate** — split the work, each takes a piece
- **Mark as built** — when complete, update the title with `✅ [BUILT]` and add the GitHub link

### Posting format
```
Title: ✅ [BUILT] Your Skill Name

Status: Live on GitHub
Repo: https://github.com/YOUR_USERNAME/YOUR_REPO

Description: What it does, how it helps SEs day-to-day.
```

### High-value skill categories (based on SE feedback)
- SE Engagement Logger (Salesforce automation)
- POV Status Updater
- Customer-facing trend reports (like this project)
- Pre-call research automation
- RFP / competitive response helpers

---

## Project README Best Practices (for GitHub)

A good README = more stars = higher leaderboard ranking.

### Structure
```markdown
# Tool Name

> **One-line hook that states the problem it solves**

[badges: Python version, dependencies, offline status]

---

## What It Does
Answer the CISO-level question this tool addresses.
- Bullet: chart/feature 1
- Bullet: chart/feature 2

## Quick Start
[Minimal code block to get running in 60 seconds]

## How It Works
[Brief API/technical overview]

## Files
[Table of files and their purpose]

## Troubleshooting
[Common errors and fixes]
```

### Writing tips
- Open with the **problem**, not the technical solution
- Frame around the question a CISO or security manager asks
- Keep Quick Start under 5 commands
- Add troubleshooting for the top 3-4 errors

---

## Key Contacts

| Person | Role | Contact |
|--------|------|---------|
| DJ Zito | SE Program Leader | Slack |
| Justin Buchanan | Agentic AI Accelerator Practice | Slack |
| Joel Barnes | ACE Factory / Ideas Portal | Slack |

---

## Lessons Learned (from first submission)

| Issue | Solution |
|-------|---------|
| `lastMitigated` filter uses days, not timestamps | `"0:7"` = last 7 days |
| Charts don't render via `innerHTML` | Use iframe `srcdoc` + inline Chart.js |
| Python 3.6 missing `datetime.fromisoformat` | Use `datetime.strptime(s[:10], "%Y-%m-%d")` |
| GitHub HTTPS auth fails | Use PAT token: `https://username:TOKEN@github.com/...` |
| Exchange repo is private | Fork first, then submit PR from your fork |
| Edge blocks CDN scripts | Open HTML report in Chrome |

---

*Guide compiled: June 2026 · Benny Adler, Tenable*
