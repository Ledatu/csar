package configsource

import (
	"context"
	"fmt"
	"os"
	"strconv"
)

// FileSource loads configuration from a local file.
type FileSource struct {
	path string
}

// NewFileSource creates a FileSource that reads from the given path.
func NewFileSource(path string) *FileSource {
	return &FileSource{path: path}
}

// Fetch reads the file and returns its contents.
// ETag is derived from the file's modification time and size for cheap
// change detection without reading the full file on every poll.
func (s *FileSource) Fetch(_ context.Context) (FetchedConfig, error) {
	info, err := os.Stat(s.path)
	if err != nil {
		return FetchedConfig{}, fmt.Errorf("stat config file %s: %w", s.path, err)
	}

	etag := "mtime:" + strconv.FormatInt(info.ModTime().UnixNano(), 10) +
		":size:" + strconv.FormatInt(info.Size(), 10)

	data, err := os.ReadFile(s.path)
	if err != nil {
		return FetchedConfig{}, fmt.Errorf("reading config file %s: %w", s.path, err)
	}

	return FetchedConfig{
		Data: data,
		ETag: etag,
	}, nil
}
