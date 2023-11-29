package iamsdk

import (
	"sync"

	"github.com/anhvietnguyennva/iam-go-sdk/global"
	"github.com/anhvietnguyennva/iam-go-sdk/sdk"
)

var sdkLock sync.Mutex
var setSDKLock sync.Mutex

func SDK() sdk.ISDK {
	sdkLock.Lock()
	defer sdkLock.Unlock()
	if global.SDK() == nil {
		global.SetSDK(sdk.New())
	}
	return global.SDK()
}

func SetSDK(s sdk.ISDK) {
	setSDKLock.Lock()
	defer setSDKLock.Unlock()
	global.SetSDK(s)
}
