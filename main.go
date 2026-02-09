package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

var version = "dev"

// releaseArtifactExtensions lists extensions that indicate release artifacts
// requiring integrity verification.
var releaseArtifactExtensions = map[string]bool{
	".tar.gz":  true,
	".tgz":     true,
	".zip":     true,
	".tar.bz2": true,
	".tar.xz":  true,
	".deb":     true,
	".rpm":     true,
	".whl":     true,
	".gem":     true,
	".jar":     true,
	".war":     true,
	".apk":     true,
}

// signatureExtensions lists extensions used for artifact signatures.
var signatureExtensions = map[string]bool{
	".sig":     true,
	".asc":     true,
	".sign":    true,
	".gpg":     true,
	".minisig": true,
}

// checksumExtensions lists extensions used for checksum files.
var checksumExtensions = map[string]bool{
	".sha256":    true,
	".sha512":    true,
	".sha256sum": true,
	".sha512sum": true,
	".md5":       true,
	".md5sum":    true,
}

// checksumFileNames lists common names for checksum manifest files.
var checksumFileNames = map[string]bool{
	"SHA256SUMS":     true,
	"SHA512SUMS":     true,
	"CHECKSUMS":      true,
	"checksums.txt":  true,
	"CHECKSUMS.txt":  true,
}

// lockfileNames lists lockfile names that contain checksums to verify.
var lockfileNames = map[string]bool{
	"package-lock.json": true,
	"yarn.lock":         true,
	"go.sum":            true,
	"Gemfile.lock":      true,
	"poetry.lock":       true,
	"Cargo.lock":        true,
	"composer.lock":     true,
}

// reChecksumLine matches a hex checksum followed by a filename in checksum files.
var reChecksumLine = regexp.MustCompile(`^([a-fA-F0-9]{32,128})\s+(.+)$`)

// skippedDirs contains directory names to skip during recursive walks.
var skippedDirs = map[string]bool{
	".git":         true,
	"vendor":       true,
	"node_modules": true,
	"__pycache__":  true,
	".venv":        true,
}

func buildServer() *sdk.PluginServer {
	manifest := sdk.NewManifest("nox/artifact-integrity", version).
		Capability("artifact-integrity", "Release verification, build comparison, and artifact signing detection").
		Tool("scan", "Scan for missing checksums, unsigned artifacts, and checksum mismatches", true).
		Done().
		Safety(sdk.WithRiskClass(sdk.RiskPassive)).
		Build()

	return sdk.NewPluginServer(manifest).
		HandleTool("scan", handleScan)
}

func handleScan(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	workspaceRoot, _ := req.Input["workspace_root"].(string)
	if workspaceRoot == "" {
		workspaceRoot = req.WorkspaceRoot
	}

	resp := sdk.NewResponse()

	if workspaceRoot == "" {
		return resp.Build(), nil
	}

	// Collect all files first for cross-referencing.
	var allFiles []string
	fileSet := make(map[string]bool)

	err := filepath.WalkDir(workspaceRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		allFiles = append(allFiles, path)
		fileSet[path] = true
		return nil
	})
	if err != nil && err != context.Canceled {
		return nil, fmt.Errorf("walking workspace: %w", err)
	}

	// Analyze files.
	for _, path := range allFiles {
		if ctx.Err() != nil {
			break
		}

		name := filepath.Base(path)
		dir := filepath.Dir(path)

		// Check release artifacts for missing checksums and signatures.
		if isReleaseArtifact(name) {
			checkMissingChecksum(resp, path, name, dir, fileSet)
			checkUnsignedArtifact(resp, path, name, dir, fileSet)
		}

		// Check checksum files for mismatches.
		if checksumFileNames[name] {
			checkChecksumMismatches(resp, path, dir)
		}

		// Check lockfiles for integrity issues.
		if lockfileNames[name] {
			checkLockfileIntegrity(resp, path)
		}
	}

	return resp.Build(), nil
}

// isReleaseArtifact checks whether a filename has a release artifact extension.
func isReleaseArtifact(name string) bool {
	lower := strings.ToLower(name)
	for ext := range releaseArtifactExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// hasCompanionFile checks if a file with any of the given extensions exists
// alongside the artifact.
func hasCompanionFile(name, dir string, fileSet map[string]bool, extensions map[string]bool) bool {
	for ext := range extensions {
		companion := filepath.Join(dir, name+ext)
		if fileSet[companion] {
			return true
		}
	}
	return false
}

// checkMissingChecksum reports when a release artifact has no corresponding checksum file.
func checkMissingChecksum(resp *sdk.ResponseBuilder, path, name, dir string, fileSet map[string]bool) {
	if hasCompanionFile(name, dir, fileSet, checksumExtensions) {
		return
	}

	// Check whether a bulk checksum file exists in the same directory.
	for csName := range checksumFileNames {
		if fileSet[filepath.Join(dir, csName)] {
			return
		}
	}

	resp.Finding(
		"ARTINT-001",
		sdk.SeverityHigh,
		sdk.ConfidenceHigh,
		fmt.Sprintf("Release artifact %s has no corresponding checksum file", name),
	).
		At(path, 0, 0).
		WithMetadata("artifact", name).
		WithMetadata("type", "missing_checksum").
		Done()
}

// checkUnsignedArtifact reports when a release artifact has no signature file.
func checkUnsignedArtifact(resp *sdk.ResponseBuilder, path, name, dir string, fileSet map[string]bool) {
	if hasCompanionFile(name, dir, fileSet, signatureExtensions) {
		return
	}

	resp.Finding(
		"ARTINT-002",
		sdk.SeverityMedium,
		sdk.ConfidenceMedium,
		fmt.Sprintf("Release artifact %s has no signature file (.sig, .asc)", name),
	).
		At(path, 0, 0).
		WithMetadata("artifact", name).
		WithMetadata("type", "unsigned_artifact").
		Done()
}

// checkChecksumMismatches reads a checksum manifest file and verifies that
// referenced files match their declared checksums.
func checkChecksumMismatches(resp *sdk.ResponseBuilder, checksumFilePath, dir string) {
	f, err := os.Open(checksumFilePath)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		matches := reChecksumLine.FindStringSubmatch(line)
		if len(matches) != 3 {
			continue
		}

		declaredHash := strings.ToLower(matches[1])
		referencedFile := strings.TrimSpace(matches[2])
		// Handle BSD-style prefix.
		referencedFile = strings.TrimPrefix(referencedFile, "*")

		targetPath := filepath.Join(dir, referencedFile)
		data, err := os.ReadFile(targetPath)
		if err != nil {
			// File not found -- not a mismatch, just missing.
			continue
		}

		// Compute SHA-256 (most common for 64-char hashes).
		if len(declaredHash) == 64 {
			h := sha256.Sum256(data)
			actualHash := hex.EncodeToString(h[:])
			if actualHash != declaredHash {
				resp.Finding(
					"ARTINT-003",
					sdk.SeverityCritical,
					sdk.ConfidenceHigh,
					fmt.Sprintf("Checksum mismatch for %s: declared=%s actual=%s", referencedFile, declaredHash[:16]+"...", actualHash[:16]+"..."),
				).
					At(checksumFilePath, lineNum, lineNum).
					WithMetadata("file", referencedFile).
					WithMetadata("type", "checksum_mismatch").
					Done()
			}
		}
	}
}

// npmLockfile represents a minimal package-lock.json structure.
type npmLockfile struct {
	Packages map[string]struct {
		Version   string `json:"version"`
		Resolved  string `json:"resolved"`
		Integrity string `json:"integrity"`
	} `json:"packages"`
}

// checkLockfileIntegrity inspects lockfiles for missing or inconsistent
// integrity metadata.
func checkLockfileIntegrity(resp *sdk.ResponseBuilder, filePath string) {
	name := filepath.Base(filePath)

	switch name {
	case "package-lock.json":
		checkNPMLockfileIntegrity(resp, filePath)
	case "go.sum":
		checkGoSumIntegrity(resp, filePath)
	}
}

// checkNPMLockfileIntegrity checks package-lock.json for missing integrity hashes.
func checkNPMLockfileIntegrity(resp *sdk.ResponseBuilder, filePath string) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return
	}

	var lockfile npmLockfile
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return
	}

	for pkgPath, pkg := range lockfile.Packages {
		if pkgPath == "" {
			continue // root package
		}
		if pkg.Integrity == "" && pkg.Resolved != "" {
			resp.Finding(
				"ARTINT-003",
				sdk.SeverityCritical,
				sdk.ConfidenceHigh,
				fmt.Sprintf("Lockfile entry missing integrity hash: %s@%s", pkgPath, pkg.Version),
			).
				At(filePath, 0, 0).
				WithMetadata("package", pkgPath).
				WithMetadata("version", pkg.Version).
				WithMetadata("type", "missing_integrity").
				Done()
		}
	}
}

// reGoSumLine matches go.sum lines: module version hash.
var reGoSumLine = regexp.MustCompile(`^(\S+)\s+(\S+)\s+(h1:\S+)$`)

// checkGoSumIntegrity validates the format of go.sum entries.
func checkGoSumIntegrity(resp *sdk.ResponseBuilder, filePath string) {
	f, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	seen := make(map[string]string) // module@version -> hash

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		matches := reGoSumLine.FindStringSubmatch(line)
		if len(matches) != 4 {
			continue
		}

		module := matches[1]
		ver := matches[2]
		hash := matches[3]
		key := module + "@" + ver

		if existing, ok := seen[key]; ok && existing != hash {
			resp.Finding(
				"ARTINT-003",
				sdk.SeverityCritical,
				sdk.ConfidenceHigh,
				fmt.Sprintf("Duplicate go.sum entry with different hash for %s", key),
			).
				At(filePath, lineNum, lineNum).
				WithMetadata("module", module).
				WithMetadata("version", ver).
				WithMetadata("type", "checksum_mismatch").
				Done()
		}
		seen[key] = hash
	}
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	srv := buildServer()
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "nox-plugin-artifact-integrity: %v\n", err)
		os.Exit(1)
	}
}
