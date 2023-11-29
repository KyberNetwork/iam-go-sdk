package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/anhvietnguyennva/iam-go-sdk/constant"
	"github.com/anhvietnguyennva/iam-go-sdk/oauth/dto"
	"github.com/anhvietnguyennva/iam-go-sdk/oauth/entity"
	"github.com/anhvietnguyennva/iam-go-sdk/util/env"
)

func GetJWKs() (map[string]*entity.JWK, error) {
	endpoint := env.StringFromEnv(constant.EnvKeyOAuthGetJWKsURL, constant.OAuthGetJWKsDefaultURL)
	res, err := http.Get(endpoint)
	if err != nil {
		return nil, err
	}
	bodyJson, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("encountered error when calling %s: %v", endpoint, err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("encountered error when calling %s, status code: %d, response: %s", endpoint, res.StatusCode, bodyJson)
	}
	var responseBody dto.GetJWKsResponse
	err = json.Unmarshal(bodyJson, &responseBody)
	if err != nil {
		return nil, fmt.Errorf("encountered error when attempting unmarshal response from %s: %v", endpoint, err)
	}

	jwks := responseBody.ToEntities()
	ret := make(map[string]*entity.JWK, len(jwks))
	for _, jwk := range jwks {
		ret[jwk.Kid] = jwk
	}
	return ret, nil
}

func ExchangeToken(clientID string, clientSecret string) (string, int64, error) {
	endpoint := env.StringFromEnv(constant.EnvKeyOAuthExchangeTokenURL, constant.OAuthExchangeTokenDefaultURL)
	params := url.Values{}
	params.Set("grant_type", constant.OAuthGrantTypeClientCredentials)
	params.Set("client_id", clientID)
	params.Set("client_secret", clientSecret)
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	bodyJson, err := io.ReadAll(res.Body)
	if err != nil {
		return "", 0, fmt.Errorf("encountered error when calling %s: %v", endpoint, err)
	}
	if res.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("encountered error when calling %s, status code: %d, response: %s", endpoint, res.StatusCode, bodyJson)
	}
	var responseBody dto.ExchangeTokenResponse
	err = json.Unmarshal(bodyJson, &responseBody)
	if err != nil {
		return "", 0, fmt.Errorf("encountered error when attempting unmarshal response from %s: %v", endpoint, err)
	}

	expirationTime := time.Now().Unix() + responseBody.ExpiresIn - 30 // minus 30 seconds to ensure that token does not expire when it is being used

	return responseBody.AccessToken, expirationTime, nil
}
