package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/anhvietnguyennva/iam-go-sdk/constant"
	"github.com/anhvietnguyennva/iam-go-sdk/permission/dto"
	"github.com/anhvietnguyennva/iam-go-sdk/util/env"
)

func CheckPermission(namespace string, object string, relation string, subjectID string, maxDepth uint8) (bool, error) {
	endpoint, err := url.Parse(env.StringFromEnv(constant.EnvKeyPermissionCheckPermissionsURL, constant.IAMPermissionCheckPermissionsDefaultURL))
	if err != nil {
		return false, err
	}
	params := url.Values{}
	params.Add("namespace", namespace)
	params.Add("object", object)
	params.Add("relation", relation)
	params.Add("subjectId", subjectID)
	params.Add("maxDepth", strconv.Itoa(int(maxDepth)))
	endpoint.RawQuery = params.Encode()

	res, err := http.Get(endpoint.String())
	if err != nil {
		return false, err
	}
	bodyJson, err := io.ReadAll(res.Body)
	if err != nil {
		return false, fmt.Errorf("encountered error when calling %s: %v", endpoint, err)
	}
	if res.StatusCode != http.StatusOK {
		return false, fmt.Errorf("encountered error when calling %s, status code: %d, response: %s", endpoint, res.StatusCode, bodyJson)
	}
	var responseBody dto.CheckPermissionResponse
	err = json.Unmarshal(bodyJson, &responseBody)
	if err != nil {
		return false, fmt.Errorf("encountered error when attempting unmarshal response from %s: %v", endpoint, err)
	}

	return responseBody.Data.Allowed, nil
}

func CreatePermission(request *dto.CreatePermissionRequest, bearerAccessToken string) (string, error) {
	endpoint := env.StringFromEnv(constant.EnvKeyPermissionCreateSubjectRelationTupleURL, constant.IAMPermissionCreateSubjectRelationTupleDefaultURL)
	marshalledReq, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(marshalledReq))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", bearerAccessToken)
	client := http.Client{}

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	bodyJson, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("encountered error when calling %s: %v", endpoint, err)
	}
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("encountered error when calling %s, status code: %d, response: %s", endpoint, res.StatusCode, bodyJson)
	}
	var responseBody dto.CreatePermissionResponse
	err = json.Unmarshal(bodyJson, &responseBody)
	if err != nil {
		return "", fmt.Errorf("encountered error when attempting unmarshal response from %s: %v", endpoint, err)
	}

	return responseBody.Data.ID, nil
}
