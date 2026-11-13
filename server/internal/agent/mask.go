package agent

import (
	"regexp"
	"strings"
)

// Masking runs on the node, before anything leaves it (NFR-2.3): credentials never reach the control plane or
// ClickHouse.

const masked = "[masked]"

var sensitiveHeaders = map[string]bool{"authorization": true, "proxy-authorization": true, "x-api-key": true, "x-auth-token": true, "x-csrf-token": true}

const sensitiveKey = `pass(?:word|wd)?|pwd|secret|token|api[_-]?key|authorization|session(?:_?id)?|card(?:_?number)?|cvv|ssn|pin`

var (
	sensitiveName = regexp.MustCompile(`(?i)(?:` + sensitiveKey + `)`)
	formField     = regexp.MustCompile(`(?i)((?:^|[&;])[^=&;]*(?:` + sensitiveKey + `)[^=&;]*=)[^&;]*`)
	jsonField     = regexp.MustCompile(`(?i)("[^"]*(?:` + sensitiveKey + `)[^"]*"\s*:\s*)("(?:[^"\\]|\\.)*"|[^,}\s]+)`)
)

// MaskHeaders returns a copy with credential headers replaced and every cookie value hidden.
func MaskHeaders(h map[string][]string) map[string]string {
	out := make(map[string]string, len(h))
	for k, vs := range h {
		v := strings.Join(vs, ", ")
		switch lk := strings.ToLower(k); {
		case sensitiveHeaders[lk]:
			v = masked
		case lk == "cookie":
			parts := strings.Split(v, ";")
			for i, p := range parts {
				if name, _, ok := strings.Cut(strings.TrimSpace(p), "="); ok {
					parts[i] = name + "=" + masked
				}
			}
			v = strings.Join(parts, "; ")
		}
		if len(v) > 1024 {
			v = v[:1024]
		}
		out[k] = v
	}
	return out
}

// MaskBody hides sensitive fields in form-encoded and JSON bodies and truncates the result.
func MaskBody(body string) string {
	if len(body) > 4096 {
		body = body[:4096]
	}
	body = formField.ReplaceAllString(body, "${1}"+masked)
	return jsonField.ReplaceAllString(body, `${1}"`+masked+`"`)
}

// MaskMatch hides matched data when the matched variable is itself a secret (ARGS:password and the like).
func MaskMatch(variable, data string) string {
	if _, key, ok := strings.Cut(variable, ":"); ok && sensitiveName.MatchString(key) {
		return masked
	}
	if strings.HasPrefix(variable, "REQUEST_COOKIES") || strings.EqualFold(variable, "REQUEST_HEADERS:Authorization") {
		return masked
	}
	return data
}
