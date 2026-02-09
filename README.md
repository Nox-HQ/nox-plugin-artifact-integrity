# nox-plugin-artifact-integrity

**Verify checksums, signatures, and lockfile integrity for release artifacts.**

<!-- badges -->
![Track: Supply Chain](https://img.shields.io/badge/track-Supply%20Chain-green)
![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)
![Go 1.25+](https://img.shields.io/badge/go-1.25%2B-00ADD8)

---

## Overview

`nox-plugin-artifact-integrity` verifies the integrity of release artifacts, build outputs, and dependency lockfiles. It detects release archives (`.tar.gz`, `.zip`, `.deb`, `.rpm`, `.whl`, `.jar`, etc.) that lack corresponding checksum files, unsigned artifacts missing GPG/minisign signatures, checksum mismatches where a declared hash does not match the actual file content, and lockfile integrity issues in `package-lock.json` and `go.sum`.

Supply chain attacks increasingly target the space between "build" and "deploy." An attacker who can replace a release artifact without detection has compromised the entire delivery pipeline. This plugin enforces the fundamental supply chain security principle: every artifact must have a verifiable checksum, and every checksum must match. It also catches lockfile integrity issues -- missing integrity hashes in `package-lock.json` and duplicate entries with conflicting hashes in `go.sum` -- that indicate tampering or corruption in dependency resolution.

The plugin performs actual SHA-256 hash computation for checksum verification, comparing declared hashes in checksum manifest files against the computed hashes of referenced files. This is not pattern matching -- it is cryptographic verification.

## Use Cases

### Release Pipeline Verification

Your CI/CD pipeline produces `.tar.gz` archives for distribution. Before publishing, this plugin verifies that every archive has a corresponding `.sha256` or `SHA256SUMS` file, and that every entry in the checksum file matches the actual artifact. A checksum mismatch at this stage indicates either a corrupted build or a tampered artifact.

### Signed Release Enforcement

Your organization's security policy requires that all release artifacts be cryptographically signed. This plugin flags every `.tar.gz`, `.zip`, `.deb`, `.rpm`, `.whl`, `.jar`, and `.gem` file that lacks a corresponding `.sig`, `.asc`, or `.minisig` signature file, ensuring that no unsigned artifact ships.

### Lockfile Integrity Monitoring

A compromised `package-lock.json` with missing integrity hashes means npm cannot verify that downloaded packages match their expected content. This plugin scans lockfiles and flags packages with `resolved` URLs but missing `integrity` fields. For `go.sum`, it detects duplicate module entries with conflicting hashes that indicate potential tampering.

### Post-Build Audit

After a build completes, run this plugin against the build output directory to verify that all artifacts, checksums, and signatures are consistent before promoting to the next environment.

## 5-Minute Demo

### Prerequisites

- Go 1.25+
- [Nox](https://github.com/Nox-HQ/nox) installed

### Quick Start

1. **Install the plugin**

   ```bash
   nox plugin install Nox-HQ/nox-plugin-artifact-integrity
   ```

2. **Create test files**

   ```bash
   mkdir -p demo/release

   # Create a release artifact without checksum or signature
   echo "binary content" > demo/release/myapp-v1.2.0-linux-amd64.tar.gz

   # Create a checksum file with a wrong hash
   echo "0000000000000000000000000000000000000000000000000000000000000000  myapp-v1.2.0-linux-amd64.tar.gz" > demo/release/SHA256SUMS
   ```

   `demo/package-lock.json`:
   ```json
   {
     "name": "my-app",
     "lockfileVersion": 3,
     "packages": {
       "": { "name": "my-app", "version": "1.0.0" },
       "node_modules/lodash": {
         "version": "4.17.21",
         "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
         "integrity": ""
       }
     }
   }
   ```

3. **Run the scan**

   ```bash
   nox scan --plugin nox/artifact-integrity demo/
   ```

4. **Review findings**

   ```
   nox-plugin-artifact-integrity: 3 findings

   ARTINT-002 [MEDIUM] Release artifact myapp-v1.2.0-linux-amd64.tar.gz has no
     signature file (.sig, .asc)
     demo/release/myapp-v1.2.0-linux-amd64.tar.gz:0:0
     type: unsigned_artifact

   ARTINT-003 [CRITICAL] Checksum mismatch for myapp-v1.2.0-linux-amd64.tar.gz:
     declared=0000000000000000... actual=a1b2c3d4e5f6a7b8...
     demo/release/SHA256SUMS:1:1
     type: checksum_mismatch

   ARTINT-003 [CRITICAL] Lockfile entry missing integrity hash:
     node_modules/lodash@4.17.21
     demo/package-lock.json:0:0
     type: missing_integrity
   ```

## Rules

| ID | Description | Severity | Confidence | CWE |
|----|-------------|----------|------------|-----|
| ARTINT-001 | Release artifact has no corresponding checksum file | High | High | -- |
| ARTINT-002 | Release artifact has no signature file (.sig, .asc, .gpg, .minisig) | Medium | Medium | -- |
| ARTINT-003 | Checksum mismatch, missing integrity hash, or duplicate conflicting hash | Critical | High | -- |

### Recognized Artifact Extensions

`.tar.gz`, `.tgz`, `.zip`, `.tar.bz2`, `.tar.xz`, `.deb`, `.rpm`, `.whl`, `.gem`, `.jar`, `.war`, `.apk`

### Recognized Signature Extensions

`.sig`, `.asc`, `.sign`, `.gpg`, `.minisig`

### Recognized Checksum Extensions and Manifest Names

`.sha256`, `.sha512`, `.sha256sum`, `.sha512sum`, `.md5`, `.md5sum`, `SHA256SUMS`, `SHA512SUMS`, `CHECKSUMS`, `checksums.txt`, `CHECKSUMS.txt`

### Recognized Lockfiles

`package-lock.json`, `yarn.lock`, `go.sum`, `Gemfile.lock`, `poetry.lock`, `Cargo.lock`, `composer.lock`

## Supported File Types

This plugin does not scan source code by language. Instead, it analyzes:

- **Release artifacts** -- Binary archives and packages identified by extension
- **Checksum files** -- SHA256SUMS and similar manifest files
- **Lockfiles** -- `package-lock.json` (JSON parsing for integrity fields), `go.sum` (line format validation)

## Configuration

This plugin requires no configuration.

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| _None_ | This plugin has no environment variables | -- |

## Installation

### Via Nox (recommended)

```bash
nox plugin install Nox-HQ/nox-plugin-artifact-integrity
```

### Standalone

```bash
git clone https://github.com/Nox-HQ/nox-plugin-artifact-integrity.git
cd nox-plugin-artifact-integrity
go build -o nox-plugin-artifact-integrity .
```

## Development

```bash
# Build
go build ./...

# Run tests
go test ./...

# Run a specific test
go test ./... -run TestChecksumMismatch

# Lint
golangci-lint run

# Run in Docker
docker build -t nox-plugin-artifact-integrity .
docker run --rm nox-plugin-artifact-integrity
```

## Architecture

The plugin is built on the Nox plugin SDK and communicates via the Nox plugin protocol over stdio.

**Scan pipeline:**

1. **Workspace walk and file collection** -- Recursively traverses the workspace root (skipping `.git`, `vendor`, `node_modules`, `__pycache__`, `.venv`). All files are collected into a list and a set for O(1) lookup.

2. **Release artifact analysis** -- For each file with a release artifact extension:
   - **Missing checksum check (ARTINT-001):** Looks for companion files with checksum extensions (e.g., `myapp.tar.gz.sha256`) and checks for bulk checksum manifest files (e.g., `SHA256SUMS`) in the same directory. Reports if neither exists.
   - **Unsigned artifact check (ARTINT-002):** Looks for companion files with signature extensions (e.g., `myapp.tar.gz.sig`, `myapp.tar.gz.asc`). Reports if no signature file is found.

3. **Checksum manifest verification (ARTINT-003)** -- For files named `SHA256SUMS`, `CHECKSUMS`, etc., parses each line as `<hash> <filename>`. For 64-character hex hashes (SHA-256), reads the referenced file, computes its SHA-256 hash, and compares against the declared hash. Mismatches are reported as critical findings.

4. **Lockfile integrity (ARTINT-003)** -- For `package-lock.json`, parses the JSON and checks each package entry for missing `integrity` fields. For `go.sum`, parses each line and detects duplicate module entries with conflicting hashes.

5. **Output** -- Findings include artifact names, checksum fragments, and integrity metadata.

## Contributing

Contributions are welcome. Please open an issue first to discuss proposed changes.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-check`)
3. Write tests for new integrity checks
4. Ensure `go test ./...` and `golangci-lint run` pass
5. Submit a pull request

## License

Apache-2.0
