package configsource

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	coresrc "github.com/ledatu/csar-core/configsource"
	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/statestore"
)

type failingRouteStore struct {
	statestore.StateStore
	fail      bool
	writes    int
	failAfter int
}

func (s *failingRouteStore) PutRoute(ctx context.Context, entry statestore.RouteEntry) error {
	if s.fail || (s.failAfter > 0 && s.writes >= s.failAfter) {
		return errors.New("route write failed")
	}
	s.writes++
	return s.StateStore.PutRoute(ctx, entry)
}

func TestRollbackReconcilesPartiallyWrittenRoutes(t *testing.T) {
	store := &failingRouteStore{StateStore: statestore.NewMemoryStore()}
	defer store.Close()
	path := filepath.Join(t.TempDir(), "config.yaml")
	const original = `listen_addr: ":8080"
paths:
  /original:
    get:
      x-csar-backend:
        target_url: https://original.example
`
	write := func(data string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(original)
	var commits int
	w := NewConfigWatcherWithOptions(coresrc.NewFileSource(path), store,
		slog.New(slog.NewTextHandler(io.Discard, nil)), []WatcherOption{
			WithOnConfigApplied(func(*config.Config) { commits++ }),
		})
	ctx := context.Background()
	if _, err := w.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	store.failAfter = store.writes + 1
	write(original + `  /added-one:
    get:
      x-csar-backend:
        target_url: https://one.example
  /added-two:
    get:
      x-csar-backend:
        target_url: https://two.example
`)
	if _, err := w.Apply(ctx); err == nil || commits != 1 {
		t.Fatal("partial route write was published")
	}
	routes, err := store.GetRoutes(ctx)
	if err != nil || len(routes) != 2 {
		t.Fatalf("expected one partially written route: %v", err)
	}
	store.failAfter = 0
	write(original)
	if _, err := w.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	routes, err = store.GetRoutes(ctx)
	if err != nil || len(routes) != 1 || routes[0].Path != "/original" || commits != 2 {
		t.Fatal("rollback left a partially written route behind")
	}
}

func TestOnConfigAppliedWaitsForSuccessfulWrites(t *testing.T) {
	store := &failingRouteStore{StateStore: statestore.NewMemoryStore(), fail: true}
	defer store.Close()
	path := filepath.Join(t.TempDir(), "config.yaml")
	const routes = `listen_addr: ":8080"
paths:
  /preferences:
    get:
      x-csar-backend:
        target_url: https://user-preferences:8080
`
	writeConfig := func(data string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig(routes)
	var applied []*config.Config
	w := NewConfigWatcherWithOptions(coresrc.NewFileSource(path), store,
		slog.New(slog.NewTextHandler(io.Discard, nil)), []WatcherOption{
			WithOnConfigApplied(func(cfg *config.Config) { applied = append(applied, cfg) }),
		})
	ctx := context.Background()
	if _, err := w.Apply(ctx); err == nil || len(applied) != 0 {
		t.Fatal("failed route write must not publish top-level config")
	}
	store.fail = false
	if _, err := w.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 || store.writes != 1 {
		t.Fatalf("callbacks = %d, writes = %d", len(applied), store.writes)
	}
	writeConfig(routes + "ssrf_protection:\n  allowed_internal_hosts: [user-preferences]\n")
	if changed, err := w.Apply(ctx); err != nil || !changed {
		t.Fatalf("policy-only Apply = %v, %v", changed, err)
	}
	if len(applied) != 2 || store.writes != 1 || applied[1].SSRF == nil {
		t.Fatal("policy-only apply must publish new config without rewriting routes")
	}
	writeConfig("paths: [invalid")
	if _, err := w.Apply(ctx); err == nil || len(applied) != 2 {
		t.Fatal("invalid YAML must not publish top-level config")
	}
}
