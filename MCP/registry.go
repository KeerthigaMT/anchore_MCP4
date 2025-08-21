package main

import (
	"github.com/anchore-engine-api-server/mcp-server/config"
	"github.com/anchore-engine-api-server/mcp-server/models"
	tools_archives "github.com/anchore-engine-api-server/mcp-server/tools/archives"
	tools_registries "github.com/anchore-engine-api-server/mcp-server/tools/registries"
	tools_query "github.com/anchore-engine-api-server/mcp-server/tools/query"
	tools_general "github.com/anchore-engine-api-server/mcp-server/tools/general"
	tools_images "github.com/anchore-engine-api-server/mcp-server/tools/images"
	tools_system "github.com/anchore-engine-api-server/mcp-server/tools/system"
	tools_user_management "github.com/anchore-engine-api-server/mcp-server/tools/user_management"
	tools_events "github.com/anchore-engine-api-server/mcp-server/tools/events"
	tools_repository_credentials "github.com/anchore-engine-api-server/mcp-server/tools/repository_credentials"
	tools_identity "github.com/anchore-engine-api-server/mcp-server/tools/identity"
	tools_imports "github.com/anchore-engine-api-server/mcp-server/tools/imports"
	tools_version "github.com/anchore-engine-api-server/mcp-server/tools/version"
	tools_policies "github.com/anchore-engine-api-server/mcp-server/tools/policies"
	tools_health "github.com/anchore-engine-api-server/mcp-server/tools/health"
	tools_subscriptions "github.com/anchore-engine-api-server/mcp-server/tools/subscriptions"
	tools_summaries "github.com/anchore-engine-api-server/mcp-server/tools/summaries"
)

func GetAll(cfg *config.APIConfig) []models.Tool {
	return []models.Tool{
		tools_archives.CreateArchive_image_analysisTool(cfg),
		tools_archives.CreateList_analysis_archiveTool(cfg),
		tools_registries.CreateList_registriesTool(cfg),
		tools_registries.CreateCreate_registryTool(cfg),
		tools_query.CreateQuery_images_by_packageTool(cfg),
		tools_general.CreatePingTool(cfg),
		tools_images.CreateDelete_imageTool(cfg),
		tools_images.CreateGet_imageTool(cfg),
		tools_system.CreateDelete_feedTool(cfg),
		tools_system.CreateToggle_feed_enabledTool(cfg),
		tools_user_management.CreateDelete_user_credentialTool(cfg),
		tools_user_management.CreateList_user_credentialsTool(cfg),
		tools_user_management.CreateCreate_user_credentialTool(cfg),
		tools_system.CreateList_servicesTool(cfg),
		tools_archives.CreateDelete_analysis_archive_ruleTool(cfg),
		tools_archives.CreateGet_analysis_archive_ruleTool(cfg),
		tools_images.CreateList_image_metadataTool(cfg),
		tools_events.CreateList_event_typesTool(cfg),
		tools_images.CreateGet_image_content_by_type_imageidTool(cfg),
		tools_query.CreateQuery_vulnerabilitiesTool(cfg),
		tools_images.CreateGet_image_vulnerabilities_by_type_imageidTool(cfg),
		tools_archives.CreateList_archivesTool(cfg),
		tools_repository_credentials.CreateAdd_repositoryTool(cfg),
		tools_images.CreateGet_image_policy_check_by_imageidTool(cfg),
		tools_images.CreateGet_image_content_by_type_javapackageTool(cfg),
		tools_system.CreateGet_services_by_nameTool(cfg),
		tools_system.CreateDescribe_error_codesTool(cfg),
		tools_images.CreateList_image_content_by_imageidTool(cfg),
		tools_identity.CreateGet_userTool(cfg),
		tools_images.CreateGet_image_vulnerability_typesTool(cfg),
		tools_imports.CreateList_import_image_configsTool(cfg),
		tools_imports.CreateImport_image_configTool(cfg),
		tools_images.CreateDelete_images_asyncTool(cfg),
		tools_images.CreateList_imagesTool(cfg),
		tools_images.CreateAdd_imageTool(cfg),
		tools_images.CreateList_secret_search_resultsTool(cfg),
		tools_images.CreateDelete_image_by_imageidTool(cfg),
		tools_images.CreateGet_image_by_imageidTool(cfg),
		tools_events.CreateDelete_eventTool(cfg),
		tools_events.CreateGet_eventTool(cfg),
		tools_system.CreateGet_system_feedsTool(cfg),
		tools_system.CreatePost_system_feedsTool(cfg),
		tools_imports.CreateCreate_operationTool(cfg),
		tools_imports.CreateList_operationsTool(cfg),
		tools_images.CreateGet_image_metadata_by_typeTool(cfg),
		tools_system.CreateDescribe_policyTool(cfg),
		tools_user_management.CreateUpdate_account_stateTool(cfg),
		tools_system.CreateDelete_feed_groupTool(cfg),
		tools_system.CreateToggle_group_enabledTool(cfg),
		tools_images.CreateGet_image_content_by_type_malwareTool(cfg),
		tools_images.CreateGet_image_policy_checkTool(cfg),
		tools_system.CreateTest_webhookTool(cfg),
		tools_user_management.CreateDelete_userTool(cfg),
		tools_user_management.CreateGet_account_userTool(cfg),
		tools_version.CreateVersion_checkTool(cfg),
		tools_images.CreateGet_image_vulnerability_types_by_imageidTool(cfg),
		tools_images.CreateGet_image_content_by_type_filesTool(cfg),
		tools_user_management.CreateList_accountsTool(cfg),
		tools_user_management.CreateCreate_accountTool(cfg),
		tools_imports.CreateInvalidate_operationTool(cfg),
		tools_imports.CreateGet_operationTool(cfg),
		tools_identity.CreateGet_credentialsTool(cfg),
		tools_identity.CreateAdd_credentialTool(cfg),
		tools_imports.CreateList_import_dockerfilesTool(cfg),
		tools_imports.CreateImport_image_dockerfileTool(cfg),
		tools_images.CreateGet_image_content_by_type_imageid_javapackageTool(cfg),
		tools_policies.CreateDelete_policyTool(cfg),
		tools_policies.CreateGet_policyTool(cfg),
		tools_policies.CreateUpdate_policyTool(cfg),
		tools_health.CreateHealth_checkTool(cfg),
		tools_images.CreateGet_image_content_by_type_imageid_filesTool(cfg),
		tools_subscriptions.CreateUpdate_subscriptionTool(cfg),
		tools_subscriptions.CreateDelete_subscriptionTool(cfg),
		tools_subscriptions.CreateGet_subscriptionTool(cfg),
		tools_registries.CreateDelete_registryTool(cfg),
		tools_registries.CreateGet_registryTool(cfg),
		tools_registries.CreateUpdate_registryTool(cfg),
		tools_system.CreateGet_statusTool(cfg),
		tools_archives.CreateList_analysis_archive_rulesTool(cfg),
		tools_archives.CreateCreate_analysis_archive_ruleTool(cfg),
		tools_images.CreateList_file_content_search_resultsTool(cfg),
		tools_archives.CreateGet_archived_analysisTool(cfg),
		tools_archives.CreateDelete_archived_analysisTool(cfg),
		tools_system.CreateGet_service_detailTool(cfg),
		tools_events.CreateList_eventsTool(cfg),
		tools_events.CreateDelete_eventsTool(cfg),
		tools_policies.CreateList_policiesTool(cfg),
		tools_policies.CreateAdd_policyTool(cfg),
		tools_images.CreateGet_image_vulnerabilities_by_typeTool(cfg),
		tools_imports.CreateImport_image_packagesTool(cfg),
		tools_imports.CreateList_import_packagesTool(cfg),
		tools_user_management.CreateDelete_accountTool(cfg),
		tools_user_management.CreateGet_accountTool(cfg),
		tools_imports.CreateList_import_image_manifestsTool(cfg),
		tools_subscriptions.CreateList_subscriptionsTool(cfg),
		tools_subscriptions.CreateAdd_subscriptionTool(cfg),
		tools_identity.CreateGet_users_accountTool(cfg),
		tools_user_management.CreateList_usersTool(cfg),
		tools_user_management.CreateCreate_userTool(cfg),
		tools_system.CreateDelete_serviceTool(cfg),
		tools_system.CreateGet_services_by_name_and_hostTool(cfg),
		tools_images.CreateList_image_contentTool(cfg),
		tools_imports.CreateList_import_parent_manifestsTool(cfg),
		tools_images.CreateGet_image_content_by_typeTool(cfg),
		tools_summaries.CreateList_imagetagsTool(cfg),
		tools_images.CreateList_retrieved_filesTool(cfg),
		tools_query.CreateQuery_images_by_vulnerabilityTool(cfg),
	}
}
