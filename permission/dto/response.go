package dto

type CheckPermissionResData struct {
	Allowed bool `json:"allowed"`
}

type CheckPermissionResponse struct {
	Code    int64                  `json:"code"`
	Message string                 `json:"message"`
	Data    CheckPermissionResData `json:"data"`
}

type CreatePermissionResData struct {
	ID string `json:"id"`
}

type CreatePermissionResponse struct {
	Code    int64                   `json:"code"`
	Message string                  `json:"message"`
	Data    CreatePermissionResData `json:"data"`
}

type CreatePermissionMultipleObjectsResData struct {
	IDs []string `json:"ids"`
}

type CreatePermissionMultipleObjectsResponse struct {
	Code    int64                                  `json:"code"`
	Message string                                 `json:"message"`
	Data    CreatePermissionMultipleObjectsResData `json:"data"`
}
