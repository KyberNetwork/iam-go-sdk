package cache

import "strings"

const (
	KeyJWKPrefix         = "jwk"
	KeyAccessTokenPrefix = "access_token"

	KeyDelimiter = ":"
)

func Key(parts ...string) string {
	return strings.Join(parts, KeyDelimiter)
}
