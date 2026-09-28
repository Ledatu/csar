// Package routepattern compiles route path templates such as
// "/svc/{marketplace}/{id:[0-9]+}/items/{rest:.*}" and orders them by how
// precisely they describe a request path, so that the router and the
// simulator pick the same route for the same request.
package routepattern

import (
	"regexp"
	"strings"
)

// maxRegexLength is the maximum allowed length for a compiled regex pattern string.
// This prevents ReDoS attacks from overly complex regex configurations (audit §2.2.4).
const maxRegexLength = 1024

// dangerousPatterns detects regex constructs known to cause catastrophic backtracking.
// These include nested quantifiers like (a+)+, (a*)+, (a+)*, etc.
var dangerousPatterns = regexp.MustCompile(`\([^)]*[+*][^)]*\)[+*]|\(\?[^)]*\)[+*]`)

// Compile converts a path containing {var} or {var:regex} segments into an
// anchored regexp. It returns the regexp, the variable names in order, and
// true if the path has variables; plain paths return nil, nil, false.
//
// Security audit §2.2.4: rejects patterns that are too long or contain known
// catastrophic backtracking constructs.
//
// Examples:
//
//	"/api/v1/users/{id:[0-9]+}"         → "^/api/v1/users/([0-9]+)$"
//	"/api/{version:v[0-9]+}/items/{id}" → "^/api/(v[0-9]+)/items/([^/]+)$"
//	"/api/v1/products"                  → nil, nil, false
func Compile(path string) (*regexp.Regexp, []string, bool) {
	if !strings.Contains(path, "{") {
		return nil, nil, false
	}

	var b strings.Builder
	var varNames []string
	b.WriteString("^")

	for _, tok := range tokenize(path) {
		switch {
		case !tok.variable:
			b.WriteString(regexp.QuoteMeta(tok.text))
		case !tok.hasPattern:
			varNames = append(varNames, tok.text)
			b.WriteString("([^/]+)")
		default:
			if dangerousPatterns.MatchString(tok.pattern) {
				return nil, nil, false
			}
			varNames = append(varNames, tok.text)
			b.WriteString("(")
			b.WriteString(tok.pattern)
			b.WriteString(")")
		}
	}

	b.WriteString("$")

	pattern := b.String()
	if len(pattern) > maxRegexLength {
		return nil, nil, false
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, nil, false
	}
	return re, varNames, true
}

type segmentKind int

const (
	wildcardSegment segmentKind = iota
	plainVarSegment
	constrainedVarSegment
	mixedSegment
	literalSegment
)

// Specificity ranks a path template for matching precedence. Build it once
// per route with SpecificityOf and compare with MorePreciseThan.
type Specificity struct {
	segments []segmentKind
	literals int
	path     string
}

// SpecificityOf ranks path. Templates are compared segment by segment from
// the left; at the first segment where they differ, the more precise kind
// wins: a literal segment, then a segment mixing literal text and variables,
// then a regex-constrained variable, then a plain {var}, and last a variable
// whose regex can span several segments, such as {rest:.*}.
func SpecificityOf(path string) Specificity {
	s := Specificity{path: path}
	var seg []token
	flush := func() {
		if len(seg) > 0 {
			s.segments = append(s.segments, classify(seg))
		}
		seg = seg[:0]
	}
	for _, tok := range tokenize(path) {
		if tok.variable {
			seg = append(seg, tok)
			continue
		}
		parts := strings.Split(tok.text, "/")
		for i, part := range parts {
			if i > 0 {
				flush()
			}
			if part != "" {
				s.literals += len(part)
				seg = append(seg, token{text: part})
			}
		}
	}
	flush()
	return s
}

// MorePreciseThan reports whether s must be tried before o. Templates of
// equal rank are ordered by more segments, then more literal characters,
// then the template text, so the order never depends on map iteration.
func (s Specificity) MorePreciseThan(o Specificity) bool {
	for i := 0; i < len(s.segments) && i < len(o.segments); i++ {
		if s.segments[i] != o.segments[i] {
			return s.segments[i] > o.segments[i]
		}
	}
	if len(s.segments) != len(o.segments) {
		return len(s.segments) > len(o.segments)
	}
	if s.literals != o.literals {
		return s.literals > o.literals
	}
	return s.path < o.path
}

func classify(seg []token) segmentKind {
	hasLiteral := false
	kind := literalSegment
	for _, tok := range seg {
		if !tok.variable {
			hasLiteral = true
			continue
		}
		k := plainVarSegment
		if tok.hasPattern {
			k = constrainedVarSegment
			if spansSegments(tok.pattern) {
				return wildcardSegment
			}
		}
		if k < kind {
			kind = k
		}
	}
	if hasLiteral && kind != literalSegment {
		return mixedSegment
	}
	return kind
}

func spansSegments(pattern string) bool {
	re, err := regexp.Compile("^(?:" + pattern + ")$")
	if err != nil {
		return false
	}
	return re.MatchString("a/b") || re.MatchString("0/0")
}

type token struct {
	text       string
	pattern    string
	variable   bool
	hasPattern bool
}

// tokenize splits a template into literal text and variables. A variable runs
// from "{" to the next "}", matching how Compile has always read templates.
func tokenize(path string) []token {
	var toks []token
	for i := 0; i < len(path); {
		open := strings.IndexByte(path[i:], '{')
		if open < 0 {
			toks = append(toks, token{text: path[i:]})
			break
		}
		if open > 0 {
			toks = append(toks, token{text: path[i : i+open]})
		}
		rest := path[i+open:]
		closeIdx := strings.IndexByte(rest, '}')
		if closeIdx < 0 {
			toks = append(toks, token{text: rest})
			break
		}
		content := rest[1:closeIdx]
		tok := token{text: content, variable: true}
		if colon := strings.IndexByte(content, ':'); colon >= 0 {
			tok.text = content[:colon]
			tok.pattern = content[colon+1:]
			tok.hasPattern = true
		}
		toks = append(toks, tok)
		i += open + closeIdx + 1
	}
	return toks
}
