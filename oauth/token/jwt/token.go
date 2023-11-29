package jwt

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/golang-jwt/jwt/v5"

	"github.com/anhvietnguyennva/iam-go-sdk/cache"
	"github.com/anhvietnguyennva/iam-go-sdk/constant"
	"github.com/anhvietnguyennva/iam-go-sdk/oauth/client"
	"github.com/anhvietnguyennva/iam-go-sdk/oauth/entity"
)

func ParseBearer(bearerAuthorization string) (*entity.AccessToken, error) {
	var bearerSchema = "Bearer "
	if len(bearerAuthorization) <= len(bearerSchema) {
		return nil, fmt.Errorf("encountered error when parsing bearer jwt: invalid bearer authorization")
	}
	return Parse(bearerAuthorization[len(bearerSchema):])
}

func Parse(tokenJWTString string) (*entity.AccessToken, error) {
	tokenJWT, err := jwt.Parse(tokenJWTString,
		func(token *jwt.Token) (interface{}, error) {
			if _, isValid := token.Method.(*jwt.SigningMethodRSA); !isValid {
				return nil, fmt.Errorf("encountered error when parsing jwt: invalid signing method: %s", token.Header["alg"])
			}

			kid := token.Header["kid"].(string)
			if kid == "" {
				return nil, errors.New("encountered error when parsing jwt: invalid token kid")
			}

			jwk, err := getJWKByKid(kid)
			if err != nil {
				return nil, err
			}

			decodedE, err := base64.RawURLEncoding.DecodeString(jwk.E)
			if err != nil {
				return nil, fmt.Errorf("encountered error when parsing jwt while decoding E: %v", err)
			}
			bigE := new(big.Int).SetBytes(decodedE)

			decodedN, err := base64.RawURLEncoding.DecodeString(jwk.N)
			if err != nil {
				return nil, fmt.Errorf("encountered error when parsing jwt while decoding N: %v", err)
			}

			bigN := new(big.Int).SetBytes(decodedN)
			return &rsa.PublicKey{
				N: bigN,
				E: int(bigE.Int64()),
			}, nil
		})

	if err != nil {
		return nil, err
	}

	if !tokenJWT.Valid {
		return nil, errors.New("encountered error when parsing jwt: token is invalid")
	}

	claims, ok := tokenJWT.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("encountered error when parsing jwt: can not convert tokenJWT.Claims to map[string]any")
	}

	clientID, ok := claims[constant.JWTClaimKeyClientID].(string)
	if !ok || clientID == "" {
		return nil, fmt.Errorf("encountered error when parsing jwt: clientID is empty or invalid format: %v", claims[constant.JWTClaimKeyClientID])
	}

	scopesJson, err := json.Marshal(claims[constant.JWTClaimKeyScopes])
	if err != nil {
		return nil, fmt.Errorf("encountered error when parsing jwt: scopes is invalid format: %v", claims[constant.JWTClaimKeyScopes])
	}
	var scopes []string
	err = json.Unmarshal(scopesJson, &scopes)
	if err != nil {
		return nil, fmt.Errorf("encountered error when parsing jwt: scopes is invalid format: %v", claims[constant.JWTClaimKeyScopes])
	}

	subject, err := tokenJWT.Claims.GetSubject()
	if err != nil {
		return nil, fmt.Errorf("encountered error when parsing jwt: subject is invalid, %s", err)
	}
	expirationTime, err := tokenJWT.Claims.GetExpirationTime()
	if err != nil {
		return nil, fmt.Errorf("encountered error when parsing jwt: expirationTime is invalid, %s", err)
	}
	issueAt, err := tokenJWT.Claims.GetIssuedAt()
	if err != nil {
		return nil, fmt.Errorf("encountered error when parsing jwt: issueAt is invalid, %s", err)
	}

	return &entity.AccessToken{
		Token:          *tokenJWT,
		ClientID:       clientID,
		Subject:        subject,
		ExpirationTime: expirationTime.UnixMilli(),
		IssueAt:        issueAt.UnixMilli(),
		Scopes:         scopes,
	}, nil
}

func getJWKByKid(kid string) (*entity.JWK, error) {
	// check cache
	cacheKey := cache.Key(cache.KeyJWKPrefix, kid)
	cached, err := cache.Get[*entity.JWK](cacheKey)
	if err == nil && cached != nil {
		return cached, nil
	}

	// get from OAuth API
	jwks, err := client.GetJWKs()
	if err != nil {
		return nil, err
	}
	jwk := jwks[kid]
	if jwk == nil {
		return nil, fmt.Errorf("encountered error when fetching jwk: not found kid %s", kid)
	}

	// set cache
	cache.Set(cacheKey, jwk)

	return jwk, nil
}
