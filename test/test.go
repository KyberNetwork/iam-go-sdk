package main

import (
	"fmt"

	iamsdk "github.com/KyberNetwork/iam-go-sdk"
)

func main() {

	// set OAUTH_GET_JWKS_URL=
	// set OAUTH_EXCHANGE_TOKEN_URL=https://oauth-api.goequitize.com/oauth2/token
	// set PERMISSION_CHECK_PERMISSIONS_URL=https://permission-api.goequitize.com/api/v1/permissions/check

	clientID := "a38f06e0-ac0e-41b6-81c8-3242b5573e5d"
	clientSecret := "8VK.~1ue23HSsNisF_DzaFweHI"

	accessToken, err := iamsdk.SDK().GetAccessToken(clientID, clientSecret)
	if err != nil {
		panic(err)
	}
	fmt.Println(accessToken)

	allowed, err := iamsdk.SDK().CheckOwnerPermission("iam-permission", "services/iam-permission", "a38f06e0-ac0e-41b6-81c8-3242b5573e5d")
	if err != nil {
		panic(err)
	}
	fmt.Println(allowed)
}
