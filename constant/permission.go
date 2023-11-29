package constant

const (
	IAMPermissionCreateSubjectRelationTupleDefaultURL = "http://iam-permission-admin-api.iam.svc:8080/admin/api/v1/subject-relation-tuples"
	IAMPermissionCheckPermissionsDefaultURL           = "http://iam-permission-public-api.iam.svc:8080/api/v1/permissions/check"

	IAMPermissionRelationViewer   = "viewer"
	IAMPermissionRelationEditor   = "editor"
	IAMPermissionRelationOwner    = "owner"
	IAMPermissionRelationConsumer = "consumer"

	IAMPermissionCheckPermissionMaxDepthDefault = 3
)
