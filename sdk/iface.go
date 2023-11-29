package sdk

import (
	"github.com/anhvietnguyennva/iam-go-sdk/oauth/entity"
	"github.com/anhvietnguyennva/iam-go-sdk/permission/dto"
)

type ISDK interface {
	ParseBearerJWT(bearerTokenJWTString string) (*entity.AccessToken, error)
	ParseJWT(tokenJWTString string) (*entity.AccessToken, error)

	GetAccessToken(clientID string, clientSecret string) (string, error)
	GetBearerAccessToken(clientID string, clientSecret string) (string, error)

	CheckPermission(namespace string, object string, relation string, subjectID string) (bool, error)
	CheckViewerPermission(namespace string, object string, subjectID string) (bool, error)
	CheckEditorPermission(namespace string, object string, subjectID string) (bool, error)
	CheckOwnerPermission(namespace string, object string, subjectID string) (bool, error)
	CheckConsumerPermission(namespace string, object string, subjectID string) (bool, error)
	CreatePermission(request *dto.CreatePermissionRequest, bearerAccessToken string) (string, error)
	CreateViewerPermission(namespace string, object string, subjectID string, bearerAccessToken string) (string, error)
	CreateEditorPermission(namespace string, object string, subjectID string, bearerAccessToken string) (string, error)
	CreateOwnerPermission(namespace string, object string, subjectID string, bearerAccessToken string) (string, error)
	CreateConsumerPermission(namespace string, object string, subjectID string, bearerAccessToken string) (string, error)
}
