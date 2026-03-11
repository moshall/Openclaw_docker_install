# Real Host Test Report (2026-03-11)

## Scope
Real-host validation for core installer flows, runtime persistence, software install paths, software scanning, and adopt/upgrade migration. Target environment covers native Docker and 1Panel Docker data roots.

## Environment
- Host: 38.54.23.183
- OS: Ubuntu 22.04
- User: root
- Docker: installed via get.docker.com (docker 29.3.0)
- Repo paths:
  - Remote clone: /root/openclaw-tests/Openclaw_docker_install
  - Local code sync (current worktree): /root/openclaw-tests/Openclaw_docker_install_local

## Test Cases and Results

### 1) Default install (Docker, official image)
- Instance: openclaw_demo
- Image: docker.io/1panel/openclaw:latest
- Data dir: /opt/openclaw/apps/openclaw_demo
- Options: bin/env/apt/cache persistence enabled, deps install enabled
- Optional software: gh, codex, clawpanel
- Skill: obsidian-skills
- Result: PASS (container running, install summary OK)

### 2) Non-preset software install
- Action: install cowsay into /root/.openclaw/software via npm
- Result: PASS (binary present in host software bin)

### 3) Runtime persistence after rebuild
- Sentinel files:
  - /root/.config/persist-check.txt
  - /root/.local/bin/persist-hello
- Rebuild with all persistence toggles enabled
- Result: PASS
  - Host runtime: /opt/openclaw/apps/openclaw_demo/runtime/root-config/persist-check.txt
  - Container: /root/.config/persist-check.txt
  - Container bin: /root/.local/bin/persist-hello

### 4) Software scan coverage (predefined vs non-preset)
- Using local code: discover_software_candidates_report
- Detected: gh, claude, codex, opencode, gemini, clawpanel, claudecodeui
- Non-preset (cowsay): not detected (expected)
- Result: PASS (predefined software detected; non-preset not in catalog)

### 5) Default software install location
- Host: /opt/openclaw/apps/openclaw_demo/software/bin
- Container: /root/.openclaw/software/bin
- Verified: gh, codex, cowsay present
- Result: PASS

### 6) Legacy -> structured layout migration
- Instance: openclaw_demo
- layout.profile:
  - LAYOUT_VERSION=2
  - MODE=upgrade-migrated-from-legacy
- Data layout after migration:
  - /opt/openclaw/apps/openclaw_demo/.openclaw
  - /opt/openclaw/apps/openclaw_demo/runtime
  - /opt/openclaw/apps/openclaw_demo/software
  - /opt/openclaw/apps/openclaw_demo/config
- Result: PASS

### 7) Fresh structured install (native Docker + 1Panel data root)
- Instances:
  - /opt/openclaw/apps/openclaw_structured (port 5213)
  - /opt/1panel/apps/openclaw_1panel_structured (port 5313)
- layout.profile:
  - LAYOUT_VERSION=2
  - MODE=fresh-structured
- openclaw.json not at root (stored under .openclaw)
- Result: PASS

### 8) Adopt non-openclawctl install + upgrade
- Manual container: openclaw_manual
- Adopt produced config: /root/.openclaw-installer/config.env
- Upgrade via adopted config succeeded; container remains healthy
- CLI check: `openclaw version` not supported by image (not a failure; use logs/health instead)
- Result: PASS

## Notes
- Gateway warnings observed (bind to non-loopback, controlUi host header fallback). These are expected given BIND=lan and compatibility flag.
- Software scanning does not include non-catalog tools (e.g., cowsay). This is expected.

## Artifacts
- /root/openclaw-tests/install.log
- /root/openclaw-tests/rebuild.log
- /root/openclaw-tests/upgrade.log
- /root/openclaw-tests/upgrade_local.log
- /root/openclaw-tests/adopt.log
- /root/openclaw-tests/adopt_upgrade.log
- /root/.openclaw-installer/deployment-info.txt
- /root/.openclaw-installer/config.env

## Cleanup Status
- Not cleaned. Active containers include:
  - openclaw_demo
  - openclaw_manual
  - openclaw_structured
  - openclaw_1panel_structured
- Data dirs retained under /opt/openclaw/apps and /opt/1panel/apps.
