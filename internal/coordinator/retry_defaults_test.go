package coordinator

import (
	"testing"

	"github.com/ledatu/csar/internal/config"
)

func TestRetrySnapshotSendsExplicitDisabledDefault(t *testing.T) {
	for _, tc := range []struct{ authored, want int }{{0, 1}, {1, 1}, {3, 3}} {
		r := &config.RetryConfig{MaxAttempts: tc.authored}
		got := retryToProto(r)
		if int(got.MaxAttempts) != tc.want {
			t.Fatalf("authored=%d wire=%d want=%d", tc.authored, got.MaxAttempts, tc.want)
		}
		if r.MaxAttempts != tc.authored {
			t.Fatal("snapshot modified authored policy")
		}
	}
}
