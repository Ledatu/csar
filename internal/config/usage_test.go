package config

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestUsageBudgetAliasesPreserveCanonicalRequest(t *testing.T) {
	var prior *UsageBudgetConfig
	for _, capacity := range []string{`"owner_seller":3`, `"owner_tenant":3`, `"owner_seller":3,"owner_tenant":3`} {
		input := `{"name":"reports","window":"1m","caller":2,"owner":4,"fleet":10,` + capacity + `}`
		for _, decode := range []func([]byte, any) error{decodeUsageJSON, yaml.Unmarshal} {
			var got UsageBudgetConfig
			if err := decode([]byte(input), &got); err != nil {
				t.Fatal(err)
			}
			if prior != nil && (!reflect.DeepEqual(prior, &got) || !reflect.DeepEqual(prior.Request("agent", "owner", "wildberries:cabinet"), got.Request("agent", "owner", "wildberries:cabinet"))) {
				t.Fatal("alias changed policy or physical debit")
			}
			prior = &got
			for _, encode := range []func(any) ([]byte, error){json.Marshal, yaml.Marshal} {
				data, err := encode(got)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(data), "owner_tenant") || !strings.Contains(string(data), "owner_seller") {
					t.Fatal("canonical output changed", string(data))
				}
			}
		}
	}
	for _, capacity := range []string{`"owner_seller":3,"owner_tenant":4`, `"owner_seller":0,"owner_tenant":3`, `"owner_tenant":0`, `"owner_tenant":1000000001`, `"owner_tenant":-1`, `"owner_tenant":null`, `"other":3`} {
		for _, decode := range []func([]byte, any) error{decodeUsageJSON, yaml.Unmarshal} {
			var got UsageBudgetConfig
			if err := decode([]byte(`{"name":"reports","window":"1m","caller":2,"owner":4,"fleet":10,`+capacity+`}`), &got); err == nil {
				t.Fatal("invalid alias accepted", capacity)
			}
		}
	}
}

// Config YAML uses strings; persisted JSON retains the existing Duration object.
func decodeUsageJSON(data []byte, target any) error {
	return json.Unmarshal([]byte(strings.ReplaceAll(string(data), `"window":"1m"`, `"window":{"Duration":60000000000}`)), target)
}
