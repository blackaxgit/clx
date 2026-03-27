# Changelog

All notable changes to CLX will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.4.0] - 2026-03-27

### Added
- `clx trust on/off/status` command for managing auto-allow mode with
  configurable duration (5m-24h), session scoping, and JSON token metadata
- `clx install` now auto-installs Ollama via Homebrew, starts the server,
  and pulls required models automatically
- `clx health` command: runs 9 concurrent system validators and reports
  status in colored table or JSON (`--json`)
- Config fields: `trust_mode_max_duration`, `trust_mode_default_duration`

### Fixed
- Flaky hook integration tests eliminated with isolated temp directories
