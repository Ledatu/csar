package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/ledatu/csar-core/usagebudget"
)

// UsageBudgetConfig groups compatible API/MCP routes under stable aggregate
// counters. Credentials, request IDs and transport are never budget dimensions.
type UsageBudgetConfig struct {
	Name   string   `yaml:"name" json:"name"`
	Window Duration `yaml:"window" json:"window"`
	Caller uint32   `yaml:"caller" json:"caller"`
	Owner  uint32   `yaml:"owner" json:"owner"`
	// OwnerSeller is the protected storage/wire name for owner + authorized tenant.
	OwnerSeller uint32 `yaml:"owner_seller" json:"owner_seller"`
	Fleet       uint32 `yaml:"fleet" json:"fleet"`
}

// usageBudgetInput accepts generic vocabulary at the configuration boundary.
// Stored JSON, coordinator protobufs and physical Redis dimensions stay canonical.
type usageBudgetInput struct {
	Name        string   `yaml:"name" json:"name"`
	Window      Duration `yaml:"window" json:"window"`
	Caller      uint32   `yaml:"caller" json:"caller"`
	Owner       uint32   `yaml:"owner" json:"owner"`
	OwnerSeller *uint32  `yaml:"owner_seller" json:"owner_seller"`
	OwnerTenant *uint32  `yaml:"owner_tenant" json:"owner_tenant"`
	Fleet       uint32   `yaml:"fleet" json:"fleet"`
}

func (in usageBudgetInput) canonical() (UsageBudgetConfig, error) {
	if in.OwnerSeller != nil && in.OwnerTenant != nil && *in.OwnerSeller != *in.OwnerTenant {
		return UsageBudgetConfig{}, fmt.Errorf("usage budget owner_tenant conflicts with owner_seller")
	}
	capacity := uint32(0)
	if in.OwnerSeller != nil {
		capacity = *in.OwnerSeller
	}
	if in.OwnerTenant != nil {
		capacity = *in.OwnerTenant
	}
	c := UsageBudgetConfig{Name: in.Name, Window: in.Window, Caller: in.Caller, Owner: in.Owner, OwnerSeller: capacity, Fleet: in.Fleet}
	if err := c.Validate(); err != nil {
		return UsageBudgetConfig{}, err
	}
	return c, nil
}

// UnmarshalYAML accepts owner_tenant and the legacy owner_seller alias.
func (c *UsageBudgetConfig) UnmarshalYAML(node *yaml.Node) error {
	var in usageBudgetInput
	if err := node.Decode(&in); err != nil {
		return err
	}
	normalized, err := in.canonical()
	if err != nil {
		return err
	}
	*c = normalized
	return nil
}

// UnmarshalJSON normalizes configuration and persisted route input identically.
func (c *UsageBudgetConfig) UnmarshalJSON(data []byte) error {
	var in usageBudgetInput
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	normalized, err := in.canonical()
	if err != nil {
		return err
	}
	*c = normalized
	return nil
}

func (c *UsageBudgetConfig) Request(callerID, owner, authorizedTenant string) usagebudget.Request {
	pair, _ := json.Marshal([]string{owner, authorizedTenant})
	hash := sha256.Sum256(pair)
	return usagebudget.Request{Policy: c.Name, Window: c.Window.Duration, Units: 1, Limits: []usagebudget.Limit{
		{Dimension: "caller", Subject: callerID, Capacity: int64(c.Caller)},
		{Dimension: "owner", Subject: owner, Capacity: int64(c.Owner)},
		// Keep this physical dimension to preserve spend across vocabulary changes.
		{Dimension: "owner_seller", Subject: hex.EncodeToString(hash[:]), Capacity: int64(c.OwnerSeller)},
		{Dimension: "fleet", Subject: "all", Capacity: int64(c.Fleet)},
	}}
}

func (c *UsageBudgetConfig) Validate() error {
	return usagebudget.Validate(c.Request("configured", "configured", "configured"))
}
