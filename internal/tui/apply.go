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
// All files are rendered and checked for conflicts before any bytes are written.
// Exclusive creation prevents concurrent writers from being overwritten without
// force; filesystem failures during writing can still leave partial output.
func ApplyGenerateResult(r *GenerateResult) error {
	outDir := r.OutputDir
	if err := os.MkdirAll(outDir, 0o750); err != nil {
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
			if _, err := os.Lstat(f.path); err == nil {
				conflicts = append(conflicts, f.path)
			} else if !os.IsNotExist(err) {
				return fmt.Errorf("checking %s: %w", f.path, err)
			}
		}
		if len(conflicts) > 0 {
			return fmt.Errorf(
				"refusing to overwrite existing file(s): %s; use --force to overwrite",
				strings.Join(conflicts, ", "),
			)
		}
	}

	// Phase 3: Create exclusively unless overwriting was requested.
	for _, f := range files {
		if err := writeConfigFile(f.path, []byte(f.content), !r.Force); err != nil {
			return fmt.Errorf("writing %s: %w", f.path, err)
		}
		fmt.Printf("  %s created: %s\n", IconCheck, f.path)
	}

	// Print summary
	printGenerateSummary(r)
	return nil
}
