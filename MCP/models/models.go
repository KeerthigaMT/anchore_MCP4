package models

import (
	"context"
	"github.com/mark3labs/mcp-go/mcp"
)

type Tool struct {
	Definition mcp.Tool
	Handler    func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error)
}

// AnalysisArchiveSource represents the AnalysisArchiveSource schema from the OpenAPI specification
type AnalysisArchiveSource struct {
	Digest string `json:"digest"` // The image digest identify the analysis. Archived analyses are based on digest, tag records are restored as analysis is restored.
}

// VulnerablePackageReference represents the VulnerablePackageReference schema from the OpenAPI specification
type VulnerablePackageReference struct {
	Severity string `json:"severity,omitempty"` // Severity of vulnerability affecting package
	TypeField string `json:"type,omitempty"` // Package type (e.g. package, rpm, deb, apk, jar, npm, gem, ...)
	Version string `json:"version,omitempty"` // A version for the package. If null, then references all versions
	Name string `json:"name,omitempty"` // Package name
	Namespace string `json:"namespace,omitempty"` // Vulnerability namespace of affected package
}

// ContentMalwareResponse represents the ContentMalwareResponse schema from the OpenAPI specification
type ContentMalwareResponse struct {
	Imagedigest string `json:"imageDigest,omitempty"`
	Content []MalwareScan `json:"content,omitempty"` // List of malware scan results, one per scanner configured to run
	Content_type string `json:"content_type,omitempty"`
}

// PolicyBundleRecord represents the PolicyBundleRecord schema from the OpenAPI specification
type PolicyBundleRecord struct {
	Active bool `json:"active,omitempty"` // True if the bundle is currently defined to be used automatically
	Created_at string `json:"created_at,omitempty"`
	Last_updated string `json:"last_updated,omitempty"`
	Policyid string `json:"policyId,omitempty"` // The bundle's identifier
	Policy_source string `json:"policy_source,omitempty"` // Source location of where the policy bundle originated
	Policybundle PolicyBundle `json:"policybundle,omitempty"` // A bundle containing a set of policies, whitelists, and rules for mapping them to specific images
	Userid string `json:"userId,omitempty"` // UserId of the user that owns the bundle
}

// AnalysisUpdateNotificationData represents the AnalysisUpdateNotificationData schema from the OpenAPI specification
type AnalysisUpdateNotificationData struct {
	Notification_type string `json:"notification_type,omitempty"`
	Notification_user string `json:"notification_user,omitempty"`
	Notification_user_email string `json:"notification_user_email,omitempty"`
	Notification_payload AnalysisUpdateNotificationPayload `json:"notification_payload,omitempty"`
}

// VulnerableImage represents the VulnerableImage schema from the OpenAPI specification
type VulnerableImage struct {
	Affected_packages []VulnerablePackageReference `json:"affected_packages,omitempty"`
	Image ImageReference `json:"image,omitempty"` // A summary of an image identity, including digest, id (if available), and any tags known to have ever been mapped to the digest
}

// AccountStatus represents the AccountStatus schema from the OpenAPI specification
type AccountStatus struct {
	State string `json:"state,omitempty"` // The status of the account
}

// TagUpdateNotificationPayload represents the TagUpdateNotificationPayload schema from the OpenAPI specification
type TagUpdateNotificationPayload struct {
	Notificationid string `json:"notificationId,omitempty"`
	Subscription_key string `json:"subscription_key,omitempty"`
	Subscription_type string `json:"subscription_type,omitempty"`
	Userid string `json:"userId,omitempty"`
	Annotations map[string]interface{} `json:"annotations,omitempty"` // List of Corresponding Image Annotations
	Curr_eval []interface{} `json:"curr_eval,omitempty"` // A list containing the current image digest
	Last_eval []interface{} `json:"last_eval,omitempty"` // A list containing the previous image digests
}

// StandaloneVulnerability represents the StandaloneVulnerability schema from the OpenAPI specification
type StandaloneVulnerability struct {
	Description string `json:"description,omitempty"` // Description of the vulnerability if available
	Namespace string `json:"namespace,omitempty"` // The namespace for the vulnerability record to avoid conflicts for the same id in different distros or sources (e.g. deb vs ubuntu for same CVE)
	References []VulnerabilityReference `json:"references,omitempty"` // List of references including
	Affected_packages []PackageReference `json:"affected_packages,omitempty"` // The array of packages (typically packages) that are vulnerable-to or provide fixes-for this vulnerability
	Severity string `json:"severity,omitempty"` // Severity label specific to the namepsace
	Vendor_data []VendorDataObject `json:"vendor_data,omitempty"` // List of Vendor Data objects
	Id string `json:"id,omitempty"` // Vulnerability identifier. May be CVE-X, RHSA-X, etc. Not necessarily unique across namespaces
	Link string `json:"link,omitempty"` // URL for the upstream CVE record in the reporting source (e.g. ubuntu security tracker)
	Nvd_data []NvdDataObject `json:"nvd_data,omitempty"` // List of Nvd Data objects
}

// ImportContentDigests represents the ImportContentDigests schema from the OpenAPI specification
type ImportContentDigests struct {
	Packages string `json:"packages"` // Digest to use for the packages content
	Parent_manifest string `json:"parent_manifest,omitempty"` // Digest for reference content for parent manifest
	Dockerfile string `json:"dockerfile,omitempty"` // Digest for reference content for dockerfile
	Image_config string `json:"image_config"` // Digest for reference content for image config
	Manifest string `json:"manifest"` // Digest to reference content for the image manifest
}

// Service represents the Service schema from the OpenAPI specification
type Service struct {
	Version string `json:"version,omitempty"` // The version of the service as reported by the service implementation on registration
	Base_url string `json:"base_url,omitempty"` // The url to reach the service, including port as needed
	Hostid string `json:"hostid,omitempty"` // The unique id of the host on which the service is executing
	Service_detail StatusResponse `json:"service_detail,omitempty"` // System status response
	Servicename string `json:"servicename,omitempty"` // Registered service name
	Status bool `json:"status,omitempty"`
	Status_message string `json:"status_message,omitempty"` // A state indicating the condition of the service. Normal operation is 'registered'
}

// AnalysisArchiveTransitionRuleExclude represents the AnalysisArchiveTransitionRuleExclude schema from the OpenAPI specification
type AnalysisArchiveTransitionRuleExclude struct {
	Expiration_days int `json:"expiration_days,omitempty"` // How long the image selected will be excluded from the archive transition
	Selector ImageSelector `json:"selector,omitempty"` // A set of selection criteria to match an image by a tagged pullstring based on its components, with regex support in each field
}

// ImageWithPackages represents the ImageWithPackages schema from the OpenAPI specification
type ImageWithPackages struct {
	Image ImageReference `json:"image,omitempty"` // A summary of an image identity, including digest, id (if available), and any tags known to have ever been mapped to the digest
	Packages []PackageReference `json:"packages,omitempty"`
}

// ImageImportContentResponse represents the ImageImportContentResponse schema from the OpenAPI specification
type ImageImportContentResponse struct {
	Created_at string `json:"created_at,omitempty"`
	Digest string `json:"digest,omitempty"`
}

// SubscriptionUpdate represents the SubscriptionUpdate schema from the OpenAPI specification
type SubscriptionUpdate struct {
	Active bool `json:"active,omitempty"` // Toggle the subscription processing on or off
	Subscription_value string `json:"subscription_value,omitempty"` // The new subscription value, e.g. the new tag to be subscribed to
}

// GroupSyncResult represents the GroupSyncResult schema from the OpenAPI specification
type GroupSyncResult struct {
	Updated_image_count int `json:"updated_image_count,omitempty"` // The number of images updated by the this group sync, across all accounts. This is typically only non-zero for vulnerability feeds which update images' vulnerability results during the sync.
	Updated_record_count int `json:"updated_record_count,omitempty"` // The number of feed data records synced down as either updates or new records
	Group string `json:"group,omitempty"` // The name of the group
	Status string `json:"status,omitempty"`
	Total_time_seconds float64 `json:"total_time_seconds,omitempty"` // The duration of the group sync in seconds
}

// ImportPackage represents the ImportPackage schema from the OpenAPI specification
type ImportPackage struct {
	Id string `json:"id,omitempty"`
	Foundby string `json:"foundBy,omitempty"`
	Licenses []string `json:"licenses"`
	Locations []ImportPackageLocation `json:"locations"`
	Metadatatype string `json:"metadataType"`
	TypeField string `json:"type"`
	Cpes []string `json:"cpes"`
	Name string `json:"name"`
	Version string `json:"version"`
	Language string `json:"language"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	Purl string `json:"purl,omitempty"`
}

// RegistryConfiguration represents the RegistryConfiguration schema from the OpenAPI specification
type RegistryConfiguration struct {
	Userid string `json:"userId,omitempty"` // Engine user that owns this registry entry
	Created_at string `json:"created_at,omitempty"`
	Last_upated string `json:"last_upated,omitempty"`
	Registry string `json:"registry,omitempty"` // hostname:port string for accessing the registry, as would be used in a docker pull operation
	Registry_name string `json:"registry_name,omitempty"` // human readable name associated with registry record
	Registry_type string `json:"registry_type,omitempty"` // Type of registry
	Registry_user string `json:"registry_user,omitempty"` // Username portion of credential to use for this registry
	Registry_verify bool `json:"registry_verify,omitempty"` // Use TLS/SSL verification for the registry URL
}

// RegistryDigestSource represents the RegistryDigestSource schema from the OpenAPI specification
type RegistryDigestSource struct {
	Tag string `json:"tag"` // A valid docker tag reference (e.g. docker.io/nginx:latest) that will be associated with the image but not used to pull the image.
	Creation_timestamp_override string `json:"creation_timestamp_override,omitempty"` // Optional override of the image creation time to support proper tag history construction in cases of out-of-order analysis compared to registry history for the tag
	Dockerfile string `json:"dockerfile,omitempty"` // Base64 encoded content of the dockerfile used to build the image, if available.
	Pullstring string `json:"pullstring"` // A digest-based pullstring (e.g. docker.io/nginx@sha256:123abc)
}

// ImportDistribution represents the ImportDistribution schema from the OpenAPI specification
type ImportDistribution struct {
	Name string `json:"name"`
	Version string `json:"version"`
	Idlike string `json:"idLike"`
}

// BaseNotificationData represents the BaseNotificationData schema from the OpenAPI specification
type BaseNotificationData struct {
	Notification_type string `json:"notification_type,omitempty"`
	Notification_user string `json:"notification_user,omitempty"`
	Notification_user_email string `json:"notification_user_email,omitempty"`
}

// ImportSource represents the ImportSource schema from the OpenAPI specification
type ImportSource struct {
	Target interface{} `json:"target"`
	TypeField string `json:"type"`
}

// AnchoreImage represents the AnchoreImage schema from the OpenAPI specification
type AnchoreImage struct {
	Created_at string `json:"created_at,omitempty"`
	Image_status string `json:"image_status,omitempty"` // State of the image
	Imagedigest string `json:"imageDigest,omitempty"`
	Userid string `json:"userId,omitempty"`
	Analysis_status string `json:"analysis_status,omitempty"` // A state value for the current status of the analysis progress of the image
	Annotations map[string]interface{} `json:"annotations,omitempty"`
	Image_content ImageContent `json:"image_content,omitempty"` // A metadata content record for a specific image, containing different content type entries
	Last_updated string `json:"last_updated,omitempty"`
	Image_detail []ImageDetail `json:"image_detail,omitempty"` // Details specific to an image reference and type such as tag and image source
	Record_version string `json:"record_version,omitempty"` // The version of the record, used for internal schema updates and data migrations.
}

// ImageReference represents the ImageReference schema from the OpenAPI specification
type ImageReference struct {
	Id string `json:"id,omitempty"` // The image id if available
	Tag_history []TagEntry `json:"tag_history,omitempty"`
	Analyzed_at string `json:"analyzed_at,omitempty"` // Timestamp, in rfc3339 format, indicating when the image state became 'analyzed' in Anchore Engine.
	Digest string `json:"digest,omitempty"` // The image digest
}

// RetrievedFile represents the RetrievedFile schema from the OpenAPI specification
type RetrievedFile struct {
	B64_content string `json:"b64_content,omitempty"`
	Path string `json:"path,omitempty"`
}

// MappingRule represents the MappingRule schema from the OpenAPI specification
type MappingRule struct {
	Policy_id string `json:"policy_id,omitempty"` // Optional single policy to evalute, if set will override any value in policy_ids, for backwards compatibility. Generally, policy_ids should be used even with a array of length 1.
	Policy_ids []string `json:"policy_ids,omitempty"` // List of policyIds to evaluate in order, to completion
	Registry string `json:"registry"`
	Repository string `json:"repository"`
	Whitelist_ids []string `json:"whitelist_ids,omitempty"`
	Id string `json:"id,omitempty"`
	Image ImageRef `json:"image"` // A reference to an image
	Name string `json:"name"`
}

// SecretSearchResult represents the SecretSearchResult schema from the OpenAPI specification
type SecretSearchResult struct {
	Matches []RegexContentMatch `json:"matches,omitempty"`
	Path string `json:"path,omitempty"`
}

// AnalysisArchiveTransitionHistory represents the AnalysisArchiveTransitionHistory schema from the OpenAPI specification
type AnalysisArchiveTransitionHistory struct {
	Rule_id string `json:"rule_id,omitempty"`
	Transition string `json:"transition,omitempty"`
	Transition_task_id string `json:"transition_task_id,omitempty"` // The task that created & updated this entry
	Created_at string `json:"created_at,omitempty"`
	Imagedigest string `json:"imageDigest,omitempty"`
	Last_updated string `json:"last_updated,omitempty"`
}

// RegistryConfigurationRequest represents the RegistryConfigurationRequest schema from the OpenAPI specification
type RegistryConfigurationRequest struct {
	Registry string `json:"registry,omitempty"` // hostname:port string for accessing the registry, as would be used in a docker pull operation. May include some or all of a repository and wildcards (e.g. docker.io/library/* or gcr.io/myproject/myrepository)
	Registry_name string `json:"registry_name,omitempty"` // human readable name associated with registry record
	Registry_pass string `json:"registry_pass,omitempty"` // Password portion of credential to use for this registry
	Registry_type string `json:"registry_type,omitempty"` // Type of registry
	Registry_user string `json:"registry_user,omitempty"` // Username portion of credential to use for this registry
	Registry_verify bool `json:"registry_verify,omitempty"` // Use TLS/SSL verification for the registry URL
}

// CVSSV2Scores represents the CVSSV2Scores schema from the OpenAPI specification
type CVSSV2Scores struct {
	Base_score float64 `json:"base_score,omitempty"`
	Exploitability_score float64 `json:"exploitability_score,omitempty"`
	Impact_score float64 `json:"impact_score,omitempty"`
}

// NvdDataObject represents the NvdDataObject schema from the OpenAPI specification
type NvdDataObject struct {
	Cvss_v2 CVSSV2Scores `json:"cvss_v2,omitempty"`
	Cvss_v3 CVSSV3Scores `json:"cvss_v3,omitempty"`
	Id string `json:"id,omitempty"` // NVD Vulnerability ID
}

// VulnUpdateNotificationPayload represents the VulnUpdateNotificationPayload schema from the OpenAPI specification
type VulnUpdateNotificationPayload struct {
	Userid string `json:"userId,omitempty"`
	Notificationid string `json:"notificationId,omitempty"`
	Subscription_key string `json:"subscription_key,omitempty"`
	Subscription_type string `json:"subscription_type,omitempty"`
	Annotations map[string]interface{} `json:"annotations,omitempty"` // List of Corresponding Image Annotations
	Diff_vulnerability_result VulnDiffResult `json:"diff_vulnerability_result,omitempty"` // The results of the comparing two vulnerability records during an update
	Imagedigest string `json:"imageDigest,omitempty"`
}

// RegexContentMatch represents the RegexContentMatch schema from the OpenAPI specification
type RegexContentMatch struct {
	Lines []int `json:"lines,omitempty"` // A list of line numbers in the file that matched the regex
	Name string `json:"name,omitempty"` // The name associated with the regular expression
	Regex string `json:"regex,omitempty"` // The regular expression used for the match
}

// User represents the User schema from the OpenAPI specification
type User struct {
	Created_at string `json:"created_at,omitempty"` // The timestampt the user record was created
	Last_updated string `json:"last_updated,omitempty"` // The timestamp of the last update to this record
	Source string `json:"source,omitempty"` // If the user is external, this is the source that the user was initialized from. All other user types have this set to null
	TypeField string `json:"type,omitempty"` // The user's type
	Username string `json:"username"` // The username to authenticate with
}

// GateSpec represents the GateSpec schema from the OpenAPI specification
type GateSpec struct {
	Description string `json:"description,omitempty"` // Description of the gate
	Name string `json:"name,omitempty"` // Gate name, as it would appear in a policy document
	State string `json:"state,omitempty"` // State of the gate and transitively all triggers it contains if not 'active'
	Superceded_by string `json:"superceded_by,omitempty"` // The name of another trigger that supercedes this on functionally if this is deprecated
	Triggers []TriggerSpec `json:"triggers,omitempty"` // List of the triggers that can fire for this Gate
}

// AnalysisArchiveRulesSummary represents the AnalysisArchiveRulesSummary schema from the OpenAPI specification
type AnalysisArchiveRulesSummary struct {
	Count int `json:"count,omitempty"` // The number of rules for this account
	Last_updated string `json:"last_updated,omitempty"` // The newest last_updated timestamp from the set of rules
}

// ServiceVersion represents the ServiceVersion schema from the OpenAPI specification
type ServiceVersion struct {
	Api map[string]interface{} `json:"api,omitempty"` // Api Version string
	Db map[string]interface{} `json:"db,omitempty"`
	Service map[string]interface{} `json:"service,omitempty"`
}

// ContentResponse represents the ContentResponse schema from the OpenAPI specification
type ContentResponse struct {
	Content []map[string]interface{} `json:"content,omitempty"`
	Content_type string `json:"content_type,omitempty"`
	Imagedigest string `json:"imageDigest,omitempty"`
}

// EventResponse represents the EventResponse schema from the OpenAPI specification
type EventResponse struct {
	Created_at string `json:"created_at,omitempty"`
	Event map[string]interface{} `json:"event,omitempty"`
	Generated_uuid string `json:"generated_uuid,omitempty"`
}

// ContentJAVAPackageResponse represents the ContentJAVAPackageResponse schema from the OpenAPI specification
type ContentJAVAPackageResponse struct {
	Imagedigest string `json:"imageDigest,omitempty"`
	Content []map[string]interface{} `json:"content,omitempty"`
	Content_type string `json:"content_type,omitempty"`
}

// ImageSelectionRule represents the ImageSelectionRule schema from the OpenAPI specification
type ImageSelectionRule struct {
	Id string `json:"id,omitempty"`
	Image ImageRef `json:"image"` // A reference to an image
	Name string `json:"name"`
	Registry string `json:"registry"`
	Repository string `json:"repository"`
}

// ImageAnalysisReport represents the ImageAnalysisReport schema from the OpenAPI specification
type ImageAnalysisReport struct {
}

// WhitelistItem represents the WhitelistItem schema from the OpenAPI specification
type WhitelistItem struct {
	Id string `json:"id,omitempty"`
	Trigger_id string `json:"trigger_id"`
	Expires_on string `json:"expires_on,omitempty"`
	Gate string `json:"gate"`
}

// AnchoreErrorCode represents the AnchoreErrorCode schema from the OpenAPI specification
type AnchoreErrorCode struct {
	Description string `json:"description,omitempty"` // Description of the error code
	Name string `json:"name,omitempty"` // Error code name
}

// PolicyEvalNotificationData represents the PolicyEvalNotificationData schema from the OpenAPI specification
type PolicyEvalNotificationData struct {
	Notification_type string `json:"notification_type,omitempty"`
	Notification_user string `json:"notification_user,omitempty"`
	Notification_user_email string `json:"notification_user_email,omitempty"`
	Notification_payload PolicyEvalNotificationPayload `json:"notification_payload,omitempty"`
}

// ImageContent represents the ImageContent schema from the OpenAPI specification
type ImageContent struct {
}

// PolicyBundle represents the PolicyBundle schema from the OpenAPI specification
type PolicyBundle struct {
	Blacklisted_images []ImageSelectionRule `json:"blacklisted_images,omitempty"` // List of mapping rules that define which images should always result in a STOP/FAIL policy result regardless of policy content or presence in whitelisted_images
	Mappings []MappingRule `json:"mappings"` // Mapping rules for defining which policy and whitelist(s) to apply to an image based on a match of the image tag or id. Evaluated in order.
	Comment string `json:"comment,omitempty"` // Description of the bundle, human readable
	Id string `json:"id"` // Id of the bundle
	Policies []Policy `json:"policies"` // Policies which define the go/stop/warn status of an image using rule matches on image properties
	Version string `json:"version"` // Version id for this bundle format
	Whitelisted_images []ImageSelectionRule `json:"whitelisted_images,omitempty"` // List of mapping rules that define which images should always be passed (unless also on the blacklist), regardless of policy result.
	Whitelists []Whitelist `json:"whitelists,omitempty"` // Whitelists which define which policy matches to disregard explicitly in the final policy decision
	Name string `json:"name,omitempty"` // Human readable name for the bundle
}

// TriggerParamSpec represents the TriggerParamSpec schema from the OpenAPI specification
type TriggerParamSpec struct {
	State string `json:"state,omitempty"` // State of the trigger parameter
	Superceded_by string `json:"superceded_by,omitempty"` // The name of another trigger that supercedes this on functionally if this is deprecated
	Validator map[string]interface{} `json:"validator,omitempty"` // If present, a definition for validation of input. Typically a jsonschema object that can be used to validate an input against.
	Description string `json:"description,omitempty"`
	Example string `json:"example,omitempty"` // An example value for the parameter (encoded as a string if the parameter is an object or list type)
	Name string `json:"name,omitempty"` // Parameter name as it appears in policy document
	Required bool `json:"required,omitempty"` // Is this a required parameter or optional
}

// ArchivedAnalysis represents the ArchivedAnalysis schema from the OpenAPI specification
type ArchivedAnalysis struct {
	Status string `json:"status,omitempty"` // The archival status
	Archive_size_bytes int `json:"archive_size_bytes,omitempty"` // The size, in bytes, of the analysis archive file
	Parentdigest string `json:"parentDigest,omitempty"` // The digest of a parent manifest (for manifest-list images)
	Created_at string `json:"created_at,omitempty"`
	Last_updated string `json:"last_updated,omitempty"`
	Analyzed_at string `json:"analyzed_at,omitempty"`
	Imagedigest string `json:"imageDigest,omitempty"` // The image digest (digest of the manifest describing the image, per docker spec)
	Image_detail []TagEntry `json:"image_detail,omitempty"` // List of tags associated with the image digest
	Annotations map[string]interface{} `json:"annotations,omitempty"` // User provided annotations as key-value pairs
}

// EventsList represents the EventsList schema from the OpenAPI specification
type EventsList struct {
	Results []EventResponse `json:"results,omitempty"` // List of events
	Item_count int `json:"item_count,omitempty"` // Number of events in this page
	Next_page bool `json:"next_page,omitempty"` // Boolean flag, True indicates there are more events and False otherwise
	Page int `json:"page,omitempty"` // Page number of this result set
}

// ImportSchema represents the ImportSchema schema from the OpenAPI specification
type ImportSchema struct {
	Version string `json:"version"`
	Url string `json:"url"`
}

// VulnDiffResult represents the VulnDiffResult schema from the OpenAPI specification
type VulnDiffResult struct {
	Removed []interface{} `json:"removed,omitempty"`
	Updated []interface{} `json:"updated,omitempty"`
	Added []interface{} `json:"added,omitempty"`
}

// PolicyRule represents the PolicyRule schema from the OpenAPI specification
type PolicyRule struct {
	Trigger string `json:"trigger"`
	Action interface{} `json:"action"`
	Gate string `json:"gate"`
	Id string `json:"id,omitempty"`
	Params []map[string]interface{} `json:"params,omitempty"`
}

// NativeSbom represents the NativeSbom schema from the OpenAPI specification
type NativeSbom struct {
}

// Whitelist represents the Whitelist schema from the OpenAPI specification
type Whitelist struct {
	Version string `json:"version"`
	Comment string `json:"comment,omitempty"`
	Id string `json:"id"`
	Items []WhitelistItem `json:"items,omitempty"`
	Name string `json:"name,omitempty"`
}

// TokenResponse represents the TokenResponse schema from the OpenAPI specification
type TokenResponse struct {
	Token string `json:"token"` // The token content
}

// TagEntry represents the TagEntry schema from the OpenAPI specification
type TagEntry struct {
	Registry string `json:"registry,omitempty"` // The registry hostname:port section of the pull string
	Repository string `json:"repository,omitempty"` // The repository section of the pull string
	Tag string `json:"tag,omitempty"` // The tag-only section of the pull string
	Detected_at string `json:"detected_at,omitempty"` // The timestamp at which the Anchore Engine detected this tag was mapped to the image digest. Does not necessarily indicate when the tag was actually pushed to the registry.
	Pullstring string `json:"pullstring,omitempty"` // The pullable string for the tag. E.g. "docker.io/library/node:latest"
}

// AccessCredential represents the AccessCredential schema from the OpenAPI specification
type AccessCredential struct {
	Created_at string `json:"created_at,omitempty"` // The timestamp of creation of the credential
	TypeField string `json:"type"` // The type of credential
	Value string `json:"value"` // The credential value (e.g. the password)
}

// PolicyEvalNotificationPayload represents the PolicyEvalNotificationPayload schema from the OpenAPI specification
type PolicyEvalNotificationPayload struct {
	Userid string `json:"userId,omitempty"`
	Notificationid string `json:"notificationId,omitempty"`
	Subscription_key string `json:"subscription_key,omitempty"`
	Subscription_type string `json:"subscription_type,omitempty"`
	Annotations map[string]interface{} `json:"annotations,omitempty"` // List of Corresponding Image Annotations
	Curr_eval map[string]interface{} `json:"curr_eval,omitempty"` // The Current Policy Evaluation result
	Last_eval map[string]interface{} `json:"last_eval,omitempty"` // The Previous Policy Evaluation result
}

// PaginatedVulnerableImageList represents the PaginatedVulnerableImageList schema from the OpenAPI specification
type PaginatedVulnerableImageList struct {
	Returned_count int `json:"returned_count,omitempty"` // The number of items sent in this response
	Next_page string `json:"next_page,omitempty"` // True if additional pages exist (page + 1) or False if this is the last page
	Page string `json:"page,omitempty"` // The page number returned (should match the requested page query string param)
	Images []VulnerableImage `json:"images,omitempty"`
}

// DeleteImageResponse represents the DeleteImageResponse schema from the OpenAPI specification
type DeleteImageResponse struct {
	Detail string `json:"detail,omitempty"`
	Digest string `json:"digest"`
	Status string `json:"status"` // Current status of the image deletion
}

// PolicyEvaluation represents the PolicyEvaluation schema from the OpenAPI specification
type PolicyEvaluation struct {
}

// TagUpdateNotificationData represents the TagUpdateNotificationData schema from the OpenAPI specification
type TagUpdateNotificationData struct {
	Notification_type string `json:"notification_type,omitempty"`
	Notification_user string `json:"notification_user,omitempty"`
	Notification_user_email string `json:"notification_user_email,omitempty"`
	Notification_payload TagUpdateNotificationPayload `json:"notification_payload,omitempty"`
}

// Vulnerability represents the Vulnerability schema from the OpenAPI specification
type Vulnerability struct {
	Nvd_data []NvdDataObject `json:"nvd_data,omitempty"` // List of Nvd Data objects
	Feed_group string `json:"feed_group,omitempty"` // The name of the feed group where vulnerability match was made
	PackageField string `json:"package,omitempty"` // The package name and version that are vulnerable in the image
	Vuln string `json:"vuln,omitempty"` // The vulnerability identifier, such as CVE-2017-100, or RHSA-2017123
	Package_version string `json:"package_version,omitempty"` // The version of the vulnerable package artifact
	Will_not_fix bool `json:"will_not_fix,omitempty"` // Whether a vendor will fix or not fix the vulnerability
	Package_cpe string `json:"package_cpe,omitempty"` // The CPE string (if applicable) describing the package to vulnerability match
	Package_path string `json:"package_path,omitempty"` // The location (if applicable) of the vulnerable package in the container filesystem
	Severity string `json:"severity,omitempty"` // The severity of the vulnerability
	Fix string `json:"fix,omitempty"` // The package containing a fix, if available
	Vendor_data []VendorDataObject `json:"vendor_data,omitempty"` // List of Vendor Data objects
	Package_name string `json:"package_name,omitempty"` // The name of the vulnerable package artifact
	Package_type string `json:"package_type,omitempty"` // The type of vulnerable package
	Feed string `json:"feed,omitempty"` // The name of the feed where vulnerability match was made
	Url string `json:"url,omitempty"` // The url for more information about the vulnerability
}

// PackageReference represents the PackageReference schema from the OpenAPI specification
type PackageReference struct {
	Will_not_fix bool `json:"will_not_fix,omitempty"` // Whether a vendor will or will not fix a vulnerabitlity
	Name string `json:"name,omitempty"` // Package name
	TypeField string `json:"type,omitempty"` // Package type (e.g. package, rpm, deb, apk, jar, npm, gem, ...)
	Version string `json:"version,omitempty"` // A version for the package. If null, then references all versions
}

// Account represents the Account schema from the OpenAPI specification
type Account struct {
	Created_at string `json:"created_at,omitempty"` // The timestamp when the account was created
	Email string `json:"email,omitempty"` // Optional email address associated with the account
	Last_updated string `json:"last_updated,omitempty"` // The timestamp of the last update to the account metadata itself (not users or creds)
	Name string `json:"name"` // The account identifier, not updatable after creation
	State string `json:"state,omitempty"` // State of the account. Disabled accounts prevent member users from logging in, deleting accounts are disabled and pending deletion and will be removed once all owned resources are garbage collected by the system
	TypeField string `json:"type,omitempty"` // The user type (admin vs user). If not specified in a POST request, 'user' is default
}

// ImageAnalysisRequest represents the ImageAnalysisRequest schema from the OpenAPI specification
type ImageAnalysisRequest struct {
	Annotations map[string]interface{} `json:"annotations,omitempty"` // Annotations to be associated with the added image in key/value form
	Created_at string `json:"created_at,omitempty"` // Optional override of the image creation time, only honored when both tag and digest are also supplied e.g. 2018-10-17T18:14:00Z. Deprecated in favor of the 'source' field
	Digest string `json:"digest,omitempty"` // A digest string for an image, maybe a pull string or just a digest. e.g. nginx@sha256:123 or sha256:abc123. If a pull string, it must have same regisry/repo as the tag field. Deprecated in favor of the 'source' field
	Dockerfile string `json:"dockerfile,omitempty"` // Base64 encoded content of the dockerfile for the image, if available. Deprecated in favor of the 'source' field.
	Image_type string `json:"image_type,omitempty"` // Optional. The type of image this is adding, defaults to "docker". This can be ommitted until multiple image types are supported.
	Source ImageSource `json:"source,omitempty"` // A set of analysis source types. Only one may be set in any given request.
	Tag string `json:"tag,omitempty"` // Full pullable tag reference for image. e.g. docker.io/nginx:latest. Deprecated in favor of the 'source' field
}

// Subscription represents the Subscription schema from the OpenAPI specification
type Subscription struct {
	Userid string `json:"userId,omitempty"` // The userId of the subscribed user
	Active bool `json:"active,omitempty"` // Is the subscription currently active
	Subscription_id string `json:"subscription_id,omitempty"` // the unique id for this subscription record
	Subscription_key string `json:"subscription_key,omitempty"` // The key value that the subscription references. E.g. a tag value or a repo name.
	Subscription_type string `json:"subscription_type,omitempty"` // The type of the subscription
	Subscription_value string `json:"subscription_value,omitempty"` // The value of the subscription target
}

// PolicyEvalNotification represents the PolicyEvalNotification schema from the OpenAPI specification
type PolicyEvalNotification struct {
	Record_state_val string `json:"record_state_val,omitempty"`
	Userid string `json:"userId,omitempty"`
	Created_at int `json:"created_at,omitempty"`
	Last_updated int `json:"last_updated,omitempty"`
	Record_state_key string `json:"record_state_key,omitempty"`
	Tries int `json:"tries,omitempty"`
	Queueid string `json:"queueId,omitempty"`
	Dataid string `json:"dataId,omitempty"`
	Max_tries int `json:"max_tries,omitempty"`
	Data PolicyEvalNotificationData `json:"data,omitempty"`
}

// ApiErrorResponse represents the ApiErrorResponse schema from the OpenAPI specification
type ApiErrorResponse struct {
	Detail map[string]interface{} `json:"detail,omitempty"` // Details structure for additional information about the error if available. Content and structure will be error specific.
	Error_type string `json:"error_type,omitempty"`
	Message string `json:"message,omitempty"`
	Code int `json:"code,omitempty"`
}

// PaginatedVulnerabilityList represents the PaginatedVulnerabilityList schema from the OpenAPI specification
type PaginatedVulnerabilityList struct {
	Next_page string `json:"next_page,omitempty"` // True if additional pages exist (page + 1) or False if this is the last page
	Page string `json:"page,omitempty"` // The page number returned (should match the requested page query string param)
	Returned_count int `json:"returned_count,omitempty"` // The number of items sent in this response
	Vulnerabilities []StandaloneVulnerability `json:"vulnerabilities,omitempty"` // The listing of matching vulnerabilities for the query subject to pagination
}

// VulnUpdateNotificationData represents the VulnUpdateNotificationData schema from the OpenAPI specification
type VulnUpdateNotificationData struct {
	Notification_type string `json:"notification_type,omitempty"`
	Notification_user string `json:"notification_user,omitempty"`
	Notification_user_email string `json:"notification_user_email,omitempty"`
	Notification_payload VulnUpdateNotificationPayload `json:"notification_payload,omitempty"`
}

// ImageSource represents the ImageSource schema from the OpenAPI specification
type ImageSource struct {
	Tag RegistryTagSource `json:"tag,omitempty"` // An image reference using a tag in a registry, this is the most common source type.
	Archive AnalysisArchiveSource `json:"archive,omitempty"` // An image reference in the analysis archive for the purposes of loading analysis from the archive into th working set
	Digest RegistryDigestSource `json:"digest,omitempty"` // An image reference using a digest in a registry, includes some extra tag and timestamp info in addition to the pull string to allow proper tag history reconstruction.
	ImportField ImageImportManifest `json:"import,omitempty"`
}

// AnalysisArchiveSummary represents the AnalysisArchiveSummary schema from the OpenAPI specification
type AnalysisArchiveSummary struct {
	Last_updated string `json:"last_updated,omitempty"` // The timestamp of the most recent archived image
	Total_data_bytes int `json:"total_data_bytes,omitempty"` // The total sum of all the bytes stored to the backing storage. Accounts for anchore-applied compression, but not compression by the underlying storage system.
	Total_image_count int `json:"total_image_count,omitempty"` // The number of unique images (digests) in the archive
	Total_tag_count int `json:"total_tag_count,omitempty"` // The number of tag records (registry/repo:tag pull strings) in the archive. This may include repeated tags but will always have a unique tag->digest mapping per record.
}

// ImagePackageManifest represents the ImagePackageManifest schema from the OpenAPI specification
type ImagePackageManifest struct {
	Distro ImportDistribution `json:"distro"`
	Schema ImportSchema `json:"schema,omitempty"`
	Source ImportSource `json:"source"`
	Artifactrelationships []ImportPackageRelationship `json:"artifactRelationships,omitempty"`
	Artifacts []ImportPackage `json:"artifacts"`
	Descriptor ImportDescriptor `json:"descriptor,omitempty"`
}

// AnchoreImageTagSummary represents the AnchoreImageTagSummary schema from the OpenAPI specification
type AnchoreImageTagSummary struct {
	Fulltag string `json:"fulltag,omitempty"`
	Created_at int `json:"created_at,omitempty"`
	Imageid string `json:"imageId,omitempty"`
	Tag_detected_at int `json:"tag_detected_at,omitempty"`
	Analysis_status string `json:"analysis_status,omitempty"`
	Analyzed_at int `json:"analyzed_at,omitempty"`
	Imagedigest string `json:"imageDigest,omitempty"`
	Image_status string `json:"image_status,omitempty"`
	Parentdigest string `json:"parentDigest,omitempty"`
}

// FileContentSearchResult represents the FileContentSearchResult schema from the OpenAPI specification
type FileContentSearchResult struct {
	Matches []RegexContentMatch `json:"matches,omitempty"`
	Path string `json:"path,omitempty"`
}

// SystemStatusResponse represents the SystemStatusResponse schema from the OpenAPI specification
type SystemStatusResponse struct {
	Service_states []Service `json:"service_states,omitempty"` // A list of service objects
}

// NotificationBase represents the NotificationBase schema from the OpenAPI specification
type NotificationBase struct {
	Created_at int `json:"created_at,omitempty"`
	Last_updated int `json:"last_updated,omitempty"`
	Record_state_key string `json:"record_state_key,omitempty"`
	Tries int `json:"tries,omitempty"`
	Queueid string `json:"queueId,omitempty"`
	Dataid string `json:"dataId,omitempty"`
	Max_tries int `json:"max_tries,omitempty"`
	Record_state_val string `json:"record_state_val,omitempty"`
	Userid string `json:"userId,omitempty"`
}

// VulnUpdateNotification represents the VulnUpdateNotification schema from the OpenAPI specification
type VulnUpdateNotification struct {
	Created_at int `json:"created_at,omitempty"`
	Last_updated int `json:"last_updated,omitempty"`
	Record_state_key string `json:"record_state_key,omitempty"`
	Tries int `json:"tries,omitempty"`
	Queueid string `json:"queueId,omitempty"`
	Dataid string `json:"dataId,omitempty"`
	Max_tries int `json:"max_tries,omitempty"`
	Record_state_val string `json:"record_state_val,omitempty"`
	Userid string `json:"userId,omitempty"`
	Data VulnUpdateNotificationData `json:"data,omitempty"`
}

// FeedSyncResult represents the FeedSyncResult schema from the OpenAPI specification
type FeedSyncResult struct {
	Feed string `json:"feed,omitempty"` // The name of the feed synced
	Groups []GroupSyncResult `json:"groups,omitempty"` // Array of group sync results
	Status string `json:"status,omitempty"` // The result of the sync operations, either co
	Total_time_seconds float64 `json:"total_time_seconds,omitempty"` // The duratin, in seconds, of the sync of the feed, the sum of all the group syncs
}

// ArchiveSummary represents the ArchiveSummary schema from the OpenAPI specification
type ArchiveSummary struct {
	Images AnalysisArchiveSummary `json:"images,omitempty"` // A summarization of the analysis archive, including size, counts, etc. This archive stores image analysis only, never the actual image content or layers.
	Rules AnalysisArchiveRulesSummary `json:"rules,omitempty"` // Summary of the transition rule set
}

// EventSubcategory represents the EventSubcategory schema from the OpenAPI specification
type EventSubcategory struct {
	Description string `json:"description,omitempty"`
	Events []EventDescription `json:"events,omitempty"`
	Name string `json:"name,omitempty"`
}

// AnalysisArchiveAddResult represents the AnalysisArchiveAddResult schema from the OpenAPI specification
type AnalysisArchiveAddResult struct {
	Detail string `json:"detail,omitempty"` // Details on the status, e.g. the error message
	Digest string `json:"digest,omitempty"` // The image digest requested to be added
	Status string `json:"status,omitempty"` // The status of the archive add operation. Typically either 'archived' or 'error'
}

// AnalysisUpdateEval represents the AnalysisUpdateEval schema from the OpenAPI specification
type AnalysisUpdateEval struct {
	Analysis_status string `json:"analysis_status,omitempty"`
	Annotations map[string]interface{} `json:"annotations,omitempty"`
	Image_digest string `json:"image_digest,omitempty"`
}

// CVSSV3Scores represents the CVSSV3Scores schema from the OpenAPI specification
type CVSSV3Scores struct {
	Base_score float64 `json:"base_score,omitempty"`
	Exploitability_score float64 `json:"exploitability_score,omitempty"`
	Impact_score float64 `json:"impact_score,omitempty"`
}

// UserCreationRequest represents the UserCreationRequest schema from the OpenAPI specification
type UserCreationRequest struct {
	Password string `json:"password"` // The initial password for the user, must be at least 6 characters, up to 128
	Username string `json:"username"` // The username to create
}

// EventCategory represents the EventCategory schema from the OpenAPI specification
type EventCategory struct {
	Category string `json:"category,omitempty"`
	Description string `json:"description,omitempty"`
	Subcategories []EventSubcategory `json:"subcategories,omitempty"`
}

// ImageRef represents the ImageRef schema from the OpenAPI specification
type ImageRef struct {
	Value string `json:"value"`
	TypeField interface{} `json:"type"`
}

// AnalysisUpdateNotification represents the AnalysisUpdateNotification schema from the OpenAPI specification
type AnalysisUpdateNotification struct {
	Queueid string `json:"queueId,omitempty"`
	Dataid string `json:"dataId,omitempty"`
	Max_tries int `json:"max_tries,omitempty"`
	Record_state_val string `json:"record_state_val,omitempty"`
	Userid string `json:"userId,omitempty"`
	Created_at int `json:"created_at,omitempty"`
	Last_updated int `json:"last_updated,omitempty"`
	Record_state_key string `json:"record_state_key,omitempty"`
	Tries int `json:"tries,omitempty"`
	Data AnalysisUpdateNotificationData `json:"data,omitempty"`
}

// RegistryTagSource represents the RegistryTagSource schema from the OpenAPI specification
type RegistryTagSource struct {
	Pullstring string `json:"pullstring"` // A docker pull string (e.g. docker.io/nginx:latest, or docker.io/nginx@sha256:abd) to retrieve the image
	Dockerfile string `json:"dockerfile,omitempty"` // Base64 encoded content of the dockerfile used to build the image, if available.
}

// ImportDescriptor represents the ImportDescriptor schema from the OpenAPI specification
type ImportDescriptor struct {
	Name string `json:"name"`
	Version string `json:"version"`
}

// MetadataResponse represents the MetadataResponse schema from the OpenAPI specification
type MetadataResponse struct {
	Metadata_type string `json:"metadata_type,omitempty"`
	Imagedigest string `json:"imageDigest,omitempty"`
	Metadata interface{} `json:"metadata,omitempty"`
}

// VendorDataObject represents the VendorDataObject schema from the OpenAPI specification
type VendorDataObject struct {
	Cvss_v3 CVSSV3Scores `json:"cvss_v3,omitempty"`
	Id string `json:"id,omitempty"` // Vendor Vulnerability ID
	Cvss_v2 CVSSV2Scores `json:"cvss_v2,omitempty"`
}

// EventDescription represents the EventDescription schema from the OpenAPI specification
type EventDescription struct {
	Message string `json:"message,omitempty"` // The message associated with the event type
	Name string `json:"name,omitempty"` // The event type. The last component of the fully-qualified event_type (category.subcategory.event)
	Resource_type string `json:"resource_type,omitempty"` // The type of resource this event is generated from
	TypeField string `json:"type,omitempty"` // The fully qualified event type as would be seen in the event payload
}

// PaginatedImageList represents the PaginatedImageList schema from the OpenAPI specification
type PaginatedImageList struct {
	Next_page string `json:"next_page,omitempty"` // True if additional pages exist (page + 1) or False if this is the last page
	Page string `json:"page,omitempty"` // The page number returned (should match the requested page query string param)
	Returned_count int `json:"returned_count,omitempty"` // The number of items sent in this response
	Images []ImageWithPackages `json:"images,omitempty"`
}

// ImportPackageLocation represents the ImportPackageLocation schema from the OpenAPI specification
type ImportPackageLocation struct {
	Layerid string `json:"layerID,omitempty"`
	Path string `json:"path"`
}

// ImageContentDeleteResponse represents the ImageContentDeleteResponse schema from the OpenAPI specification
type ImageContentDeleteResponse struct {
}

// ContentPackageResponse represents the ContentPackageResponse schema from the OpenAPI specification
type ContentPackageResponse struct {
	Content []map[string]interface{} `json:"content,omitempty"`
	Content_type string `json:"content_type,omitempty"`
	Imagedigest string `json:"imageDigest,omitempty"`
}

// MalwareScan represents the MalwareScan schema from the OpenAPI specification
type MalwareScan struct {
	Metadata map[string]interface{} `json:"metadata,omitempty"` // Open schema for scanner-specific metadata related to the scan result
	Scanner string `json:"scanner,omitempty"` // The name of the scanner that produced the finding
	Enabled bool `json:"enabled,omitempty"` // Indicates if the scanner is enabled
	Findings []map[string]interface{} `json:"findings,omitempty"`
}

// ImageDetail represents the ImageDetail schema from the OpenAPI specification
type ImageDetail struct {
	Created_at string `json:"created_at,omitempty"`
	Fulltag string `json:"fulltag,omitempty"` // Full docker-pullable tag string referencing the image
	Last_updated string `json:"last_updated,omitempty"`
	Registry string `json:"registry,omitempty"`
	Userid string `json:"userId,omitempty"`
	Dockerfile string `json:"dockerfile,omitempty"`
	Repo string `json:"repo,omitempty"`
	Fulldigest string `json:"fulldigest,omitempty"` // Full docker-pullable digest string including the registry url and repository necessary get the image
	Imagedigest string `json:"imageDigest,omitempty"` // The parent Anchore Image record to which this detail maps
	Imageid string `json:"imageId,omitempty"`
}

// AnalysisArchiveTransitionRule represents the AnalysisArchiveTransitionRule schema from the OpenAPI specification
type AnalysisArchiveTransitionRule struct {
	System_global bool `json:"system_global,omitempty"` // True if the rule applies to all accounts in the system. This is only available to admin users to update/modify, but all users with permission to list rules can see them
	Max_images_per_account int `json:"max_images_per_account,omitempty"` // This is the maximum number of image analyses an account can have. Can only be set on system_global rules
	Tag_versions_newer int `json:"tag_versions_newer,omitempty"` // Number of images mapped to the tag that are newer
	Exclude AnalysisArchiveTransitionRuleExclude `json:"exclude,omitempty"` // Which Images to exclude from auto-archiving logic
	Last_updated string `json:"last_updated,omitempty"`
	Rule_id string `json:"rule_id,omitempty"` // Unique identifier for archive rule
	Analysis_age_days int `json:"analysis_age_days,omitempty"` // Matches if the analysis is strictly older than this number of days
	Transition string `json:"transition"` // The type of transition to make. If "archive", then archive an image from the working set and remove it from the working set. If "delete", then match against archived images and delete from the archive if match.
	Created_at string `json:"created_at,omitempty"`
	Selector ImageSelector `json:"selector,omitempty"` // A set of selection criteria to match an image by a tagged pullstring based on its components, with regex support in each field
}

// LocalAnalysisSource represents the LocalAnalysisSource schema from the OpenAPI specification
type LocalAnalysisSource struct {
	Digest string `json:"digest,omitempty"`
}

// ImageSelector represents the ImageSelector schema from the OpenAPI specification
type ImageSelector struct {
	Registry string `json:"registry,omitempty"` // The registry section of a pull string. e.g. with "docker.io/anchore/anchore-engine:latest", this is "docker.io"
	Repository string `json:"repository,omitempty"` // The repository section of a pull string. e.g. with "docker.io/anchore/anchore-engine:latest", this is "anchore/anchore-engine"
	Tag string `json:"tag,omitempty"` // The tag-only section of a pull string. e.g. with "docker.io/anchore/anchore-engine:latest", this is "latest"
}

// VulnerabilityReference represents the VulnerabilityReference schema from the OpenAPI specification
type VulnerabilityReference struct {
	Source string `json:"source,omitempty"` // The reference source
	Tags []string `json:"tags,omitempty"`
	Url string `json:"url,omitempty"` // The reference url
}

// TriggerSpec represents the TriggerSpec schema from the OpenAPI specification
type TriggerSpec struct {
	Description string `json:"description,omitempty"` // Trigger description for what it tests and when it will fire during evaluation
	Name string `json:"name,omitempty"` // Name of the trigger as it would appear in a policy document
	Parameters []TriggerParamSpec `json:"parameters,omitempty"` // The list of parameters that are valid for this trigger
	State string `json:"state,omitempty"` // State of the trigger
	Superceded_by string `json:"superceded_by,omitempty"` // The name of another trigger that supercedes this on functionally if this is deprecated
}

// TagUpdateNotification represents the TagUpdateNotification schema from the OpenAPI specification
type TagUpdateNotification struct {
	Queueid string `json:"queueId,omitempty"`
	Dataid string `json:"dataId,omitempty"`
	Max_tries int `json:"max_tries,omitempty"`
	Record_state_val string `json:"record_state_val,omitempty"`
	Userid string `json:"userId,omitempty"`
	Created_at int `json:"created_at,omitempty"`
	Last_updated int `json:"last_updated,omitempty"`
	Record_state_key string `json:"record_state_key,omitempty"`
	Tries int `json:"tries,omitempty"`
	Data TagUpdateNotificationData `json:"data,omitempty"`
}

// AccountCreationRequest represents the AccountCreationRequest schema from the OpenAPI specification
type AccountCreationRequest struct {
	Email string `json:"email,omitempty"` // An optional email to associate with the account for contact purposes
	Name string `json:"name"` // The account name to use. This will identify the account and must be globally unique in the system.
}

// Annotations represents the Annotations schema from the OpenAPI specification
type Annotations struct {
}

// FeedGroupMetadata represents the FeedGroupMetadata schema from the OpenAPI specification
type FeedGroupMetadata struct {
	Created_at string `json:"created_at,omitempty"`
	Last_sync string `json:"last_sync,omitempty"`
	Name string `json:"name,omitempty"`
	Record_count int `json:"record_count,omitempty"`
}

// ImageImportManifest represents the ImageImportManifest schema from the OpenAPI specification
type ImageImportManifest struct {
	Digest string `json:"digest"`
	Local_image_id string `json:"local_image_id,omitempty"` // An "imageId" as used by Docker if available
	Operation_uuid string `json:"operation_uuid"`
	Parent_digest string `json:"parent_digest,omitempty"` // The digest of the images's manifest-list parent if it was accessed from a multi-arch tag where the tag pointed to a manifest-list. This allows preservation of that relationship in the data
	Tags []string `json:"tags"`
	Contents ImportContentDigests `json:"contents"` // Digest of content to use in the final import
}

// SubscriptionRequest represents the SubscriptionRequest schema from the OpenAPI specification
type SubscriptionRequest struct {
	Subscription_key string `json:"subscription_key,omitempty"`
	Subscription_type string `json:"subscription_type,omitempty"`
	Subscription_value string `json:"subscription_value,omitempty"`
}

// AnalysisUpdateNotificationPayload represents the AnalysisUpdateNotificationPayload schema from the OpenAPI specification
type AnalysisUpdateNotificationPayload struct {
	Notificationid string `json:"notificationId,omitempty"`
	Subscription_key string `json:"subscription_key,omitempty"`
	Subscription_type string `json:"subscription_type,omitempty"`
	Userid string `json:"userId,omitempty"`
	Curr_eval AnalysisUpdateEval `json:"curr_eval,omitempty"` // Evaluation Results for an entity (current or last)
	Last_eval AnalysisUpdateEval `json:"last_eval,omitempty"` // Evaluation Results for an entity (current or last)
	Annotations map[string]interface{} `json:"annotations,omitempty"` // List of Corresponding Image Annotations
}

// PaginationProperties represents the PaginationProperties schema from the OpenAPI specification
type PaginationProperties struct {
	Page string `json:"page,omitempty"` // The page number returned (should match the requested page query string param)
	Returned_count int `json:"returned_count,omitempty"` // The number of items sent in this response
	Next_page string `json:"next_page,omitempty"` // True if additional pages exist (page + 1) or False if this is the last page
}

// GenericNotificationPayload represents the GenericNotificationPayload schema from the OpenAPI specification
type GenericNotificationPayload struct {
	Notificationid string `json:"notificationId,omitempty"`
	Subscription_key string `json:"subscription_key,omitempty"`
	Subscription_type string `json:"subscription_type,omitempty"`
	Userid string `json:"userId,omitempty"`
}

// ImportPackageRelationship represents the ImportPackageRelationship schema from the OpenAPI specification
type ImportPackageRelationship struct {
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	Parent string `json:"parent"`
	TypeField string `json:"type"`
	Child string `json:"child"`
}

// StatusResponse represents the StatusResponse schema from the OpenAPI specification
type StatusResponse struct {
	Db_version string `json:"db_version,omitempty"`
	Detail map[string]interface{} `json:"detail,omitempty"`
	Message string `json:"message,omitempty"`
	Up bool `json:"up,omitempty"`
	Version string `json:"version,omitempty"`
	Available bool `json:"available,omitempty"`
	Busy bool `json:"busy,omitempty"`
}

// FeedMetadata represents the FeedMetadata schema from the OpenAPI specification
type FeedMetadata struct {
	Name string `json:"name,omitempty"` // name of the feed
	Updated_at string `json:"updated_at,omitempty"` // Date the metadata was last updated
	Created_at string `json:"created_at,omitempty"` // Date the metadata record was created in engine (first seen on source)
	Groups []FeedGroupMetadata `json:"groups,omitempty"`
	Last_full_sync string `json:"last_full_sync,omitempty"`
}

// ImageImportOperation represents the ImageImportOperation schema from the OpenAPI specification
type ImageImportOperation struct {
	Uuid string `json:"uuid,omitempty"`
	Created_at string `json:"created_at,omitempty"`
	Expires_at string `json:"expires_at,omitempty"`
	Status string `json:"status,omitempty"`
}

// ImageFilter represents the ImageFilter schema from the OpenAPI specification
type ImageFilter struct {
	Digest string `json:"digest,omitempty"`
	Tag string `json:"tag,omitempty"`
}

// ContentFilesResponse represents the ContentFilesResponse schema from the OpenAPI specification
type ContentFilesResponse struct {
	Imagedigest string `json:"imageDigest,omitempty"`
	Content []map[string]interface{} `json:"content,omitempty"`
	Content_type string `json:"content_type,omitempty"`
}

// VulnerabilityResponse represents the VulnerabilityResponse schema from the OpenAPI specification
type VulnerabilityResponse struct {
	Vulnerability_type string `json:"vulnerability_type,omitempty"`
	Imagedigest string `json:"imageDigest,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"` // List of Vulnerability objects
}

// Policy represents the Policy schema from the OpenAPI specification
type Policy struct {
	Rules []PolicyRule `json:"rules,omitempty"`
	Version string `json:"version"`
	Comment string `json:"comment,omitempty"`
	Id string `json:"id"`
	Name string `json:"name,omitempty"`
}
