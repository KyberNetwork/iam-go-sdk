package global

import "github.com/KyberNetwork/iam-go-sdk/sdk"

var globalSDK sdk.ISDK

func SDK() sdk.ISDK {
	return globalSDK
}

func SetSDK(s sdk.ISDK) {
	globalSDK = s
}
