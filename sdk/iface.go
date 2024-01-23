package sdk

import (
	"context"

	"google.golang.org/grpc"

	"github.com/KyberNetwork/iam-go-sdk/oauth/entity"
	"github.com/KyberNetwork/iam-go-sdk/permission/dto"
)

//go:generate mockgen -destination=sdk_mock.go -package sdk . ISDK
type ISDK interface {
	// GRPCInterceptor return a function which extracts bearer access token from metadata, parse the access token and set *entity.AccessToken into ctx
	GRPCInterceptor() func(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error)

	ParseBearerJWT(bearerTokenJWTString string) (*entity.AccessToken, error)
	ParseJWT(tokenJWTString string) (*entity.AccessToken, error)

	GetAccessToken(clientID string, clientSecret string) (string, error)
	GetBearerAccessToken(clientID string, clientSecret string) (string, error)

	CheckPermission(namespace string, object string, relation string, subjectID string) (bool, error)
	CheckPermissionOneOfObjects(namespace string, objects []string, relation string, subjectID string) (bool, error)
	CheckPermissionAllOfObjects(namespace string, objects []string, relation string, subjectID string) (bool, error)
	CheckViewerPermission(namespace string, object string, subjectID string) (bool, error)
	CheckEditorPermission(namespace string, object string, subjectID string) (bool, error)
	CheckOwnerPermission(namespace string, object string, subjectID string) (bool, error)
	CheckConsumerPermission(namespace string, object string, subjectID string) (bool, error)

	CreatePermission(request *dto.CreatePermissionRequest, bearerAccessToken string) (string, error)
	CreateViewerPermission(namespace string, object string, subjectID string, bearerAccessToken string) (string, error)
	CreateEditorPermission(namespace string, object string, subjectID string, bearerAccessToken string) (string, error)
	CreateOwnerPermission(namespace string, object string, subjectID string, bearerAccessToken string) (string, error)
	CreateConsumerPermission(namespace string, object string, subjectID string, bearerAccessToken string) (string, error)

	CreatePermissionMultipleObjects(request *dto.CreatePermissionMultipleObjectsRequest, bearerAccessToken string) ([]string, error)
	CreateViewerPermissionMultipleObjects(namespace string, objects []string, subjectID string, bearerAccessToken string) ([]string, error)
	CreateEditorPermissionMultipleObjects(namespace string, objects []string, subjectID string, bearerAccessToken string) ([]string, error)
	CreateOwnerPermissionMultipleObjects(namespace string, objects []string, subjectID string, bearerAccessToken string) ([]string, error)
	CreateConsumerPermissionMultipleObjects(namespace string, objects []string, subjectID string, bearerAccessToken string) ([]string, error)
}
