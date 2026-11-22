package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/ledatu/csar-core/usagebudget"
)

// UsageBudgetConfig groups compatible API/MCP routes under stable aggregate
// counters. Credentials, request IDs and transport are never budget dimensions.
type UsageBudgetConfig struct {
	Name        string   `yaml:"name" json:"name"`
	Window      Duration `yaml:"window" json:"window"`
	Caller      uint32   `yaml:"caller" json:"caller"`
	Owner       uint32   `yaml:"owner" json:"owner"`
	OwnerSeller uint32   `yaml:"owner_seller" json:"owner_seller"`
	Fleet       uint32   `yaml:"fleet" json:"fleet"`
}

func (c *UsageBudgetConfig) Request(callerID, owner, seller string) usagebudget.Request {
	pair, _ := json.Marshal([]string{owner, seller})
	hash := sha256.Sum256(pair)
	return usagebudget.Request{Policy: c.Name, Window: c.Window.Duration, Units: 1, Limits: []usagebudget.Limit{
		{Dimension: "caller", Subject: callerID, Capacity: int64(c.Caller)},
		{Dimension: "owner", Subject: owner, Capacity: int64(c.Owner)},
		{Dimension: "owner_seller", Subject: hex.EncodeToString(hash[:]), Capacity: int64(c.OwnerSeller)},
		{Dimension: "fleet", Subject: "all", Capacity: int64(c.Fleet)},
	}}
}

func (c *UsageBudgetConfig) Validate() error {
	return usagebudget.Validate(c.Request("configured", "configured", "configured"))
}
