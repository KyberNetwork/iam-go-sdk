package entity

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AccessToken struct {
	jwt.Token

	ClientID       string
	Subject        string
	ExpirationTime int64
	IssueAt        int64
	Scopes         []string
}

type AccessTokenString struct {
	AccessToken    string
	ExpirationTime int64
}

func (t *AccessTokenString) IsExpired() bool {
	return time.Now().Unix() > t.ExpirationTime
}
