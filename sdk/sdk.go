package sdk

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/KyberNetwork/iam-go-sdk/constant"
	"github.com/KyberNetwork/iam-go-sdk/oauth/entity"
	"github.com/KyberNetwork/iam-go-sdk/oauth/token"
	"github.com/KyberNetwork/iam-go-sdk/oauth/token/jwt"
	permissionclient "github.com/KyberNetwork/iam-go-sdk/permission/client"
	"github.com/KyberNetwork/iam-go-sdk/permission/dto"
)

type SDK struct{}

func New() *SDK {
	return &SDK{}
}

type contextKey string

const (
	CtxAccessTokenKey = contextKey(constant.CtxAccessTokenKey)
)

func (s *SDK) GRPCInterceptor() func(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	return func(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// extract bearer access token from context
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Errorf(codes.DataLoss, "failed to get metadata")
		}
		bearerAccessToken, ok := md[constant.MetadataAuthorizationKey]
		if !ok || len(bearerAccessToken) == 0 {
			return nil, status.Errorf(codes.Unauthenticated, "missing access token")
		}

		// parse bearer access token
		tokenEntity, err := s.ParseBearerJWT(bearerAccessToken[0])
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, err.Error())
		}

		// set token entity into context
		authenticatedCtx := context.WithValue(ctx, CtxAccessTokenKey, tokenEntity)

		// Call the handler to execute the server method
		resp, err := handler(authenticatedCtx, req)

		return resp, err
	}
}

func (s *SDK) ParseBearerJWT(bearerTokenJWTString string) (*entity.AccessToken, error) {
	return jwt.ParseBearer(bearerTokenJWTString)
}

func (s *SDK) ParseJWT(tokenJWTString string) (*entity.AccessToken, error) {
	return jwt.Parse(tokenJWTString)
}

func (s *SDK) GetAccessToken(clientID string, clientSecret string) (string, error) {
	return token.GetAccessToken(clientID, clientSecret)
}
func (s *SDK) GetBearerAccessToken(clientID string, clientSecret string) (string, error) {
	accessToken, err := token.GetAccessToken(clientID, clientSecret)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Bearer %s", accessToken), nil
}

func (s *SDK) CheckPermission(namespace string, object string, relation string, subjectID string) (bool, error) {
	return permissionclient.CheckPermission(namespace, object, relation, subjectID, constant.IAMPermissionCheckPermissionMaxDepthDefault)
}

func (s *SDK) CheckPermissionOneOfObjects(namespace string, objects []string, relation string, subjectID string) (bool, error) {
	for _, object := range objects {
		allowed, err := permissionclient.CheckPermission(namespace, object, relation, subjectID, constant.IAMPermissionCheckPermissionMaxDepthDefault)
		if err != nil {
			return false, err
		}
		if allowed {
			return true, nil
		}
	}
	return false, nil
}

func (s *SDK) CheckPermissionAllOfObjects(namespace string, objects []string, relation string, subjectID string) (bool, error) {
	for _, object := range objects {
		allowed, err := permissionclient.CheckPermission(namespace, object, relation, subjectID, constant.IAMPermissionCheckPermissionMaxDepthDefault)
		if err != nil {
			return false, err
		}
		if !allowed {
			return false, nil
		}
	}
	return true, nil
}

func (s *SDK) CheckViewerPermission(namespace string, object string, subjectID string) (bool, error) {
	return permissionclient.CheckPermission(namespace, object, constant.IAMPermissionRelationViewer, subjectID, constant.IAMPermissionCheckPermissionMaxDepthDefault)
}

func (s *SDK) CheckEditorPermission(namespace string, object string, subjectID string) (bool, error) {
	return permissionclient.CheckPermission(namespace, object, constant.IAMPermissionRelationEditor, subjectID, constant.IAMPermissionCheckPermissionMaxDepthDefault)
}

func (s *SDK) CheckOwnerPermission(namespace string, object string, subjectID string) (bool, error) {
	return permissionclient.CheckPermission(namespace, object, constant.IAMPermissionRelationOwner, subjectID, constant.IAMPermissionCheckPermissionMaxDepthDefault)
}
func (s *SDK) CheckConsumerPermission(namespace string, object string, subjectID string) (bool, error) {
	return permissionclient.CheckPermission(namespace, object, constant.IAMPermissionRelationConsumer, subjectID, constant.IAMPermissionCheckPermissionMaxDepthDefault)
}

func (s *SDK) CreatePermission(request *dto.CreatePermissionRequest, bearerAccessToken string) (string, error) {
	return permissionclient.CreatePermission(request, bearerAccessToken)
}

func (s *SDK) CreateViewerPermission(namespace string, object string, subjectID string, bearerAccessToken string) (string, error) {
	request := dto.CreatePermissionRequest{
		Namespace: namespace,
		Object:    object,
		Relation:  constant.IAMPermissionRelationViewer,
		SubjectID: subjectID,
	}
	return permissionclient.CreatePermission(&request, bearerAccessToken)
}

func (s *SDK) CreateEditorPermission(namespace string, object string, subjectID string, bearerAccessToken string) (string, error) {
	request := dto.CreatePermissionRequest{
		Namespace: namespace,
		Object:    object,
		Relation:  constant.IAMPermissionRelationEditor,
		SubjectID: subjectID,
	}
	return permissionclient.CreatePermission(&request, bearerAccessToken)
}

func (s *SDK) CreateOwnerPermission(namespace string, object string, subjectID string, bearerAccessToken string) (string, error) {
	request := dto.CreatePermissionRequest{
		Namespace: namespace,
		Object:    object,
		Relation:  constant.IAMPermissionRelationOwner,
		SubjectID: subjectID,
	}
	return permissionclient.CreatePermission(&request, bearerAccessToken)
}

func (s *SDK) CreateConsumerPermission(namespace string, object string, subjectID string, bearerAccessToken string) (string, error) {
	request := dto.CreatePermissionRequest{
		Namespace: namespace,
		Object:    object,
		Relation:  constant.IAMPermissionRelationConsumer,
		SubjectID: subjectID,
	}
	return permissionclient.CreatePermission(&request, bearerAccessToken)
}

func (s *SDK) CreatePermissionMultipleObjects(request *dto.CreatePermissionMultipleObjectsRequest, bearerAccessToken string) ([]string, error) {
	return permissionclient.CreatePermissionMultipleObjects(request, bearerAccessToken)
}

func (s *SDK) CreateViewerPermissionMultipleObjects(namespace string, objects []string, subjectID string, bearerAccessToken string) ([]string, error) {
	request := dto.CreatePermissionMultipleObjectsRequest{
		Namespace: namespace,
		Objects:   objects,
		Relation:  constant.IAMPermissionRelationViewer,
		SubjectID: subjectID,
	}
	return permissionclient.CreatePermissionMultipleObjects(&request, bearerAccessToken)
}

func (s *SDK) CreateEditorPermissionMultipleObjects(namespace string, objects []string, subjectID string, bearerAccessToken string) ([]string, error) {
	request := dto.CreatePermissionMultipleObjectsRequest{
		Namespace: namespace,
		Objects:   objects,
		Relation:  constant.IAMPermissionRelationEditor,
		SubjectID: subjectID,
	}
	return permissionclient.CreatePermissionMultipleObjects(&request, bearerAccessToken)
}

func (s *SDK) CreateOwnerPermissionMultipleObjects(namespace string, objects []string, subjectID string, bearerAccessToken string) ([]string, error) {
	request := dto.CreatePermissionMultipleObjectsRequest{
		Namespace: namespace,
		Objects:   objects,
		Relation:  constant.IAMPermissionRelationOwner,
		SubjectID: subjectID,
	}
	return permissionclient.CreatePermissionMultipleObjects(&request, bearerAccessToken)
}

func (s *SDK) CreateConsumerPermissionMultipleObjects(namespace string, objects []string, subjectID string, bearerAccessToken string) ([]string, error) {
	request := dto.CreatePermissionMultipleObjectsRequest{
		Namespace: namespace,
		Objects:   objects,
		Relation:  constant.IAMPermissionRelationConsumer,
		SubjectID: subjectID,
	}
	return permissionclient.CreatePermissionMultipleObjects(&request, bearerAccessToken)
}
