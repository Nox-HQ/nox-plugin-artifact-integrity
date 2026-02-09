package main

import (
	"context"
	"net"
	"path/filepath"
	"runtime"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/registry"
	"github.com/nox-hq/nox/sdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestConformance(t *testing.T) {
	srv := buildServer()
	sdk.RunConformance(t, srv)
}

func TestTrackConformance(t *testing.T) {
	srv := buildServer()
	sdk.RunForTrack(t, srv, registry.TrackSupplyChain)
}

func TestScanUnsignedReleaseMissingChecksum(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, filepath.Join(testdataDir(t), "unsigned-release"))

	found001 := findByRule(resp.GetFindings(), "ARTINT-001")
	if len(found001) == 0 {
		t.Fatal("expected at least one ARTINT-001 (missing checksum) finding for unsigned release")
	}

	for _, f := range found001 {
		if f.GetSeverity() != sdk.SeverityHigh {
			t.Errorf("ARTINT-001 severity should be HIGH, got %v", f.GetSeverity())
		}
		if f.GetMetadata()["type"] != "missing_checksum" {
			t.Errorf("expected type=missing_checksum, got %q", f.GetMetadata()["type"])
		}
	}
}

func TestScanUnsignedReleaseNoSignature(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, filepath.Join(testdataDir(t), "unsigned-release"))

	found002 := findByRule(resp.GetFindings(), "ARTINT-002")
	if len(found002) == 0 {
		t.Fatal("expected at least one ARTINT-002 (unsigned artifact) finding for unsigned release")
	}

	for _, f := range found002 {
		if f.GetSeverity() != sdk.SeverityMedium {
			t.Errorf("ARTINT-002 severity should be MEDIUM, got %v", f.GetSeverity())
		}
	}
}

func TestScanSignedReleaseNoFindings(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, filepath.Join(testdataDir(t), "signed-release"))

	found001 := findByRule(resp.GetFindings(), "ARTINT-001")
	if len(found001) != 0 {
		t.Errorf("expected no ARTINT-001 findings for signed release with checksum, got %d", len(found001))
	}

	found002 := findByRule(resp.GetFindings(), "ARTINT-002")
	if len(found002) != 0 {
		t.Errorf("expected no ARTINT-002 findings for signed release with signature, got %d", len(found002))
	}
}

func TestScanChecksumMismatch(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, filepath.Join(testdataDir(t), "checksum-mismatch"))

	found := findByRule(resp.GetFindings(), "ARTINT-003")
	if len(found) == 0 {
		t.Fatal("expected at least one ARTINT-003 (checksum mismatch) finding")
	}

	for _, f := range found {
		if f.GetSeverity() != sdk.SeverityCritical {
			t.Errorf("ARTINT-003 severity should be CRITICAL, got %v", f.GetSeverity())
		}
		if f.GetMetadata()["type"] != "checksum_mismatch" {
			t.Errorf("expected type=checksum_mismatch, got %q", f.GetMetadata()["type"])
		}
	}
}

func TestScanLockfileMissingIntegrity(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, filepath.Join(testdataDir(t), "lockfile-issue"))

	found := findByRule(resp.GetFindings(), "ARTINT-003")
	if len(found) == 0 {
		t.Fatal("expected at least one ARTINT-003 finding for lockfile missing integrity")
	}

	hasUnsafePkg := false
	for _, f := range found {
		if f.GetMetadata()["package"] == "node_modules/unsafe-pkg" {
			hasUnsafePkg = true
		}
	}
	if !hasUnsafePkg {
		t.Error("expected unsafe-pkg to be flagged for missing integrity hash")
	}
}

func TestScanEmptyWorkspace(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, t.TempDir())

	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected zero findings for empty workspace, got %d", len(resp.GetFindings()))
	}
}

func TestScanNoWorkspace(t *testing.T) {
	client := testClient(t)

	input, err := structpb.NewStruct(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "scan",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}
	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected zero findings when no workspace provided, got %d", len(resp.GetFindings()))
	}
}

func TestIsReleaseArtifact(t *testing.T) {
	tests := []struct {
		name   string
		expect bool
	}{
		{"myapp-v1.0.0.tar.gz", true},
		{"release.zip", true},
		{"package.deb", true},
		{"lib.jar", true},
		{"mylib.whl", true},
		{"main.go", false},
		{"README.md", false},
		{"Makefile", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isReleaseArtifact(tt.name)
			if got != tt.expect {
				t.Errorf("isReleaseArtifact(%q) = %v, want %v", tt.name, got, tt.expect)
			}
		})
	}
}

// --- helpers ---

func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file path")
	}
	return filepath.Join(filepath.Dir(filename), "testdata")
}

func testClient(t *testing.T) pluginv1.PluginServiceClient {
	t.Helper()
	const bufSize = 1024 * 1024

	lis := bufconn.Listen(bufSize)
	grpcServer := grpc.NewServer()
	pluginv1.RegisterPluginServiceServer(grpcServer, buildServer())

	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(func() { grpcServer.Stop() })

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	return pluginv1.NewPluginServiceClient(conn)
}

func invokeScan(t *testing.T, client pluginv1.PluginServiceClient, workspaceRoot string) *pluginv1.InvokeToolResponse {
	t.Helper()
	input, err := structpb.NewStruct(map[string]any{
		"workspace_root": workspaceRoot,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "scan",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool(scan): %v", err)
	}
	return resp
}

func findByRule(findings []*pluginv1.Finding, ruleID string) []*pluginv1.Finding {
	var result []*pluginv1.Finding
	for _, f := range findings {
		if f.GetRuleId() == ruleID {
			result = append(result, f)
		}
	}
	return result
}
