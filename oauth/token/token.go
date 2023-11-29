package token

import (
	"sync"

	"github.com/anhvietnguyennva/iam-go-sdk/cache"
	"github.com/anhvietnguyennva/iam-go-sdk/oauth/client"
	"github.com/anhvietnguyennva/iam-go-sdk/oauth/entity"
)

var lock sync.Mutex

func GetAccessToken(clientID string, clientSecret string) (string, error) {
	lock.Lock()
	defer lock.Unlock()

	// check cache
	cacheKey := cache.Key(cache.KeyAccessTokenPrefix, clientID, clientSecret)
	cached, err := cache.Get[*entity.AccessTokenString](cacheKey)
	if err == nil && cached != nil && !cached.IsExpired() {
		return cached.AccessToken, nil
	}

	// call OAuth API to exchange access token
	accessToken, expirationTime, err := client.ExchangeToken(clientID, clientSecret)
	if err != nil {
		return "", err
	}

	// set cache
	cache.Set(cacheKey, &entity.AccessTokenString{
		AccessToken:    accessToken,
		ExpirationTime: expirationTime,
	})

	return accessToken, nil
}
