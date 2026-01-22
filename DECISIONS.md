# Architectural Decisions Records (ADR)
"Why is it built this way?"

## [ACCEPTED] Webhook-Based API
**Context**: External systems need to push data to FortMesa.
**Decision**: Webhook POST with JSON payload.
**Status**: Active (V1 API).
**Benefits**:
- Simple integration for customers
- Supports batch data (assets + vulnerabilities in one call)
- TTL and deduplication support

## [ACCEPTED] Parser-per-Scanner Pattern
**Context**: Different scanners output different formats.
**Decision**: One parser per scanner in `test/` directory.
**Status**: Active.
**Parsers**: Metasploit, Nessus, NMAP, NPM Audit, OpenVAS, Qualys

## [ACCEPTED] Axios over Request
**Context**: `request` library deprecated.
**Decision**: Migrated to `axios` for HTTP calls.
**Status**: Active (v1.5+).
**Benefits**: Promise-based, maintained, smaller bundle.

## [ACCEPTED] Gzip Compression
**Context**: Large payloads (many assets/vulns).
**Decision**: Auto-gzip payloads over 4KB.
**Status**: Active (v1.5+).
**Implementation**: `transformRequest` in axios config.

## [ACCEPTED] Dual Remote Pattern
**Context**: Private development, public distribution.
**Decision**: 
- `origin` → Bitbucket (private, authoritative)
- `github` → GitHub (public mirror)
**Status**: Active.
**Release Process**: Push to origin first, then optionally sync to github.
