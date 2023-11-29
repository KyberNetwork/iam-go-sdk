package sdk

import (
	"fmt"

	"github.com/anhvietnguyennva/iam-go-sdk/constant"
	"github.com/anhvietnguyennva/iam-go-sdk/oauth/entity"
	"github.com/anhvietnguyennva/iam-go-sdk/oauth/token"
	"github.com/anhvietnguyennva/iam-go-sdk/oauth/token/jwt"
	permissionclient "github.com/anhvietnguyennva/iam-go-sdk/permission/client"
	"github.com/anhvietnguyennva/iam-go-sdk/permission/dto"
)

type SDK struct{}

func New() *SDK {
	return &SDK{}
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
