package config

import "fmt"

// ResponseCompressionConfig explicitly selects generated response encoding.
// An absent block inherits the router startup default, which is pass-through
// unless an operator explicitly enables the legacy global gzip flag.
type ResponseCompressionConfig struct {
	Mode     string `yaml:"mode" json:"mode"`
	MinBytes int32  `yaml:"min_bytes,omitempty" json:"min_bytes,omitempty"`
}

func (c *Config) ValidateResponseCompression() error {
	for path, methods := range c.Paths {
		for method := range methods {
			p := methods[method].ResponseCompression
			if p == nil {
				continue
			}
			if p.Mode != "gzip" && p.Mode != "passthrough" {
				return fmt.Errorf("route %s %s: response compression mode must be gzip or passthrough", method, path)
			}
			if p.MinBytes < 0 || p.MinBytes > 64<<10 {
				return fmt.Errorf("route %s %s: response compression min_bytes must be in 0..65536", method, path)
			}
			if p.Mode == "passthrough" && p.MinBytes != 0 {
				return fmt.Errorf("route %s %s: response compression min_bytes applies only to gzip", method, path)
			}
		}
	}
	return nil
}
