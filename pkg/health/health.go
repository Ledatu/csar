package health

import (
	"encoding/json"
	"net/http"
)

// Status represents the health status of a CSAR instance.
type Status struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

// Handler returns an HTTP handler for health checks.
func Handler(version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Status{
			Status:  "ok",
			Version: version,
		})
	}
}
