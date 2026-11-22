package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestScaffoldToolDoesNotWriteToProtocolStdout(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	original := os.Stdout
	os.Stdout = writer
	defer func() { os.Stdout = original; _ = writer.Close() }()
	result, _, callErr := handleScaffold(context.Background(), nil, ScaffoldInput{Profile: "dev-local"})
	_ = writer.Close()
	os.Stdout = original
	output, err := io.ReadAll(reader)
	if err != nil || len(output) != 0 {
		t.Fatalf("scaffold wrote non-protocol stdout (%d bytes): %v", len(output), err)
	}
	if callErr != nil || result == nil || result.IsError {
		t.Fatalf("scaffold tool failed: %v", callErr)
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatal("scaffold response is not text")
	}
	var files map[string]string
	if err := json.Unmarshal([]byte(text.Text), &files); err != nil || files["config.yaml"] == "" {
		t.Fatalf("invalid scaffold response: %v", err)
	}
}

func TestReadScaffoldFilesRejectsEscapingSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.yaml")
	if err := os.WriteFile(outside, []byte("private content"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := readScaffoldFiles(root); err == nil {
		t.Fatal("scaffold collector followed a symlink outside its root")
	}
}

func TestReadScaffoldFilesCollectsNestedFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "config.yaml"), []byte("config"), 0600); err != nil {
		t.Fatal(err)
	}
	files, err := readScaffoldFiles(root)
	if err != nil || len(files) != 1 || files["nested/config.yaml"] != "config" {
		t.Fatalf("scaffold collection failed: %v", err)
	}
}
