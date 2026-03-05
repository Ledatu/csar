package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// generatedFile is a file to be written atomically alongside others.
type generatedFile struct {
	path    string
	content string
}

// ApplyGenerateResult writes the generated config.yaml and (optionally)
// docker-compose.yaml to disk, then prints a summary.
//
// The write is atomic: all files are rendered and pre-flight checked for
// existing-file conflicts *before* any bytes are written. This prevents
// partial output where some files are written but others fail.
func ApplyGenerateResult(r *GenerateResult) error {
	outDir := r.OutputDir
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	// Phase 1: Render all content up-front.
	files := []generatedFile{
		{path: filepath.Join(outDir, "config.yaml"), content: renderConfigYAML(r)},
		{path: filepath.Join(outDir, ".env.example"), content: renderEnvExample(r)},
	}
	if r.GenerateCompose {
		files = append(files, generatedFile{
			path:    filepath.Join(outDir, "docker-compose.yaml"),
			content: renderDockerCompose(r),
		})
	}

	// Phase 2: Pre-flight — check that no target file exists (unless --force).
	if !r.Force {
		var conflicts []string
		for _, f := range files {
			if _, err := os.Stat(f.path); err == nil {
				conflicts = append(conflicts, f.path)
			}
		}
		if len(conflicts) > 0 {
			return fmt.Errorf(
				"refusing to overwrite existing file(s): %s; use --force to overwrite",
				strings.Join(conflicts, ", "),
			)
		}
	}

	// Phase 3: Write all files — no conflict check remains so partial
	// failure here is an OS-level I/O error, not a user-input issue.
	for _, f := range files {
		if err := os.WriteFile(f.path, []byte(f.content), 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", f.path, err)
		}
		fmt.Printf("  %s created: %s\n", IconCheck, f.path)
	}

	// Print summary
	printGenerateSummary(r)
	return nil
}
