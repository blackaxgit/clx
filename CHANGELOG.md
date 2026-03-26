# Changelog

All notable changes to CLX will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `clx health` command: runs 9 concurrent system validators (config, database,
  sqlite-vec, Ollama service, validator model, embedding model, hook binary,
  MCP binary, validator prompt) and reports status in colored table or JSON
  (`--json`). Exits with code 1 if any check fails.
