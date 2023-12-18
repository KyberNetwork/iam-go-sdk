package dto

type CreatePermissionRequest struct {
	Namespace string `json:"namespace"`
	Object    string `json:"object"`
	Relation  string `json:"relation"`
	SubjectID string `json:"subjectId"`
}

type CreatePermissionMultipleObjectsRequest struct {
	Namespace string   `json:"namespace"`
	Objects   []string `json:"objects"`
	Relation  string   `json:"relation"`
	SubjectID string   `json:"subjectId"`
}
