package cache

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar/pkg/middleware/authzmw"
)

var templatePlaceholder = regexp.MustCompile(`\{([^}]+)\}`)

// BuildCacheKey renders the configured key template and returns a stable hash.
func BuildCacheKey(routeKey, keyTemplate string, varyHeaders []string, keyQuery *KeyQueryConfig, namespaces map[string]int64, r *http.Request) (string, error) {
	base := keyTemplate
	if base == "" {
		base = "{method} {raw_path}"
		if keyQuery != nil {
			base = "{method} {path}"
		}
	}
	rendered, err := RenderTemplate(base, r)
	if err != nil {
		return "", err
	}

	if len(varyHeaders) > 0 {
		headers := append([]string(nil), varyHeaders...)
		sort.Strings(headers)
		for _, h := range headers {
			rendered += "\nheader:" + http.CanonicalHeaderKey(h) + "=" + r.Header.Get(h)
		}
	}
	if keyQuery != nil {
		rendered += "\nquery:" + normalizeQuery(r.URL.Query(), *keyQuery)
	}
	if len(namespaces) > 0 {
		names := make([]string, 0, len(namespaces))
		for ns := range namespaces {
			names = append(names, ns)
		}
		sort.Strings(names)
		for _, ns := range names {
			rendered += fmt.Sprintf("\nnamespace:%s=%d", ns, namespaces[ns])
		}
	}

	return hashString(routeKey + "\n" + rendered), nil
}

// KeyQueryConfig configures normalized query params appended to a cache key.
type KeyQueryConfig struct {
	Include   []string
	Exclude   []string
	Sort      bool
	DropEmpty bool
}

// RenderTags renders cache tag templates.
func RenderTags(templates []string, r *http.Request) ([]string, error) {
	tags := make([]string, 0, len(templates))
	for _, tmpl := range templates {
		tmpl = strings.TrimSpace(tmpl)
		if tmpl == "" {
			continue
		}
		tag, err := RenderTemplate(tmpl, r)
		if err != nil {
			return nil, err
		}
		tags = append(tags, tag)
	}
	return tags, nil
}

// RenderResponseTags renders tenant-aware response-derived tags.
func RenderResponseTags(configs []ResponseTag, r *http.Request, headers http.Header) ([]string, error) {
	tags := make([]string, 0)
	for _, cfg := range configs {
		if cfg.Header == "" {
			continue
		}
		raw := headers.Get(cfg.Header)
		if raw == "" {
			continue
		}
		prefix := cfg.Prefix
		if prefix != "" {
			renderedPrefix, err := RenderTemplate(prefix, r)
			if err != nil {
				return nil, err
			}
			prefix = renderedPrefix
		}
		for _, part := range strings.Split(raw, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			part = sanitizeKeyPart(part)
			if part == "" {
				continue
			}
			tags = append(tags, prefix+part)
		}
	}
	return tags, nil
}

func normalizeQuery(values url.Values, cfg KeyQueryConfig) string {
	exclude := make(map[string]struct{}, len(cfg.Exclude))
	for _, name := range cfg.Exclude {
		exclude[name] = struct{}{}
	}

	keys := append([]string(nil), cfg.Include...)
	if len(keys) == 0 {
		for key := range values {
			if _, ok := exclude[key]; ok {
				continue
			}
			keys = append(keys, key)
		}
	}
	if cfg.Sort {
		sort.Strings(keys)
	}

	out := make(url.Values)
	seenKeys := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if _, seen := seenKeys[key]; seen {
			continue
		}
		seenKeys[key] = struct{}{}
		if _, ok := exclude[key]; ok {
			continue
		}
		vals := append([]string(nil), values[key]...)
		if cfg.Sort {
			sort.Strings(vals)
		}
		for _, v := range vals {
			if cfg.DropEmpty && v == "" {
				continue
			}
			out.Add(key, v)
		}
	}
	return out.Encode()
}

// RenderTemplate resolves CSAR cache placeholders.
func RenderTemplate(tmpl string, r *http.Request) (string, error) {
	var firstErr error
	out := templatePlaceholder.ReplaceAllStringFunc(tmpl, func(match string) string {
		if firstErr != nil {
			return ""
		}
		key := templatePlaceholder.FindStringSubmatch(match)[1]
		value, err := resolvePlaceholder(key, r)
		if err != nil {
			firstErr = err
			return ""
		}
		return sanitizeKeyPart(value)
	})
	if firstErr != nil {
		return "", firstErr
	}
	return out, nil
}

func resolvePlaceholder(key string, r *http.Request) (string, error) {
	if r == nil {
		return "", fmt.Errorf("request is nil")
	}
	switch {
	case key == "method":
		return r.Method, nil
	case key == "path":
		return r.URL.Path, nil
	case key == "raw_path":
		if r.URL.RawQuery == "" {
			return r.URL.Path, nil
		}
		return r.URL.Path + "?" + r.URL.RawQuery, nil
	case key == "tenant":
		return requireValue(key, r.Header.Get(gatewayctx.HeaderTenant))
	case key == "subject":
		return requireValue(key, r.Header.Get(gatewayctx.HeaderSubject))
	case strings.HasPrefix(key, "query."):
		name := strings.TrimPrefix(key, "query.")
		return requireValue(key, r.URL.Query().Get(name))
	case strings.HasPrefix(key, "header."):
		name := strings.TrimPrefix(key, "header.")
		return requireValue(key, r.Header.Get(name))
	case strings.HasPrefix(key, "path."):
		name := strings.TrimPrefix(key, "path.")
		return requireValue(key, authzmw.PathVarsFromContext(r.Context())[name])
	default:
		return "", fmt.Errorf("unknown cache placeholder %q", key)
	}
}

func requireValue(key, value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("missing cache placeholder %q", key)
	}
	return value, nil
}

func sanitizeKeyPart(s string) string {
	if len(s) > 256 {
		s = s[:256]
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == ':' || c == '/' || c == '?' || c == '&' || c == '=' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func hashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum[:])
}
