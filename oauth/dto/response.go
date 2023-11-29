package dto

import (
	"github.com/anhvietnguyennva/iam-go-sdk/oauth/entity"
)

type GetJWKsKeyData struct {
	Use string `json:"use"`
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type GetJWKsResponse struct {
	Keys []*GetJWKsKeyData `json:"keys"`
}

func (r *GetJWKsResponse) ToEntities() []*entity.JWK {
	if r == nil || len(r.Keys) == 0 {
		return nil
	}
	ret := make([]*entity.JWK, len(r.Keys))
	for idx, k := range r.Keys {
		ret[idx] = &entity.JWK{
			Use: k.Use,
			Kty: k.Kty,
			Kid: k.Kid,
			Alg: k.Alg,
			N:   k.N,
			E:   k.E,
		}
	}
	return ret
}

type ExchangeTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
}
