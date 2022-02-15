package dnacenter

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func init() {
	// Set descriptions to support markdown syntax, this will be used in document generation
	// and the language server.
	schema.DescriptionKind = schema.StringMarkdown
}

// Provider definition of schema(configuration), resources(CRUD) operations and dataSources(query)
func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"base_url": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("DNAC_BASE_URL", nil),
				Description: "Cisco DNA Center base URL, FQDN or IP. If not set, it uses the DNAC_BASE_URL environment variable.",
			},
			"username": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("DNAC_USERNAME", nil),
				Description: "Cisco DNA Center username to authenticate. If not set, it uses the DNAC_USERNAME environment variable.",
			},
			"password": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("DNAC_PASSWORD", nil),
				Description: "Cisco DNA Center password to authenticate. If not set, it uses the DNAC_PASSWORD environment variable.",
			},
			"debug": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				DefaultFunc:  schema.EnvDefaultFunc("DNAC_DEBUG", "false"),
				ValidateFunc: validateStringHasValueFunc([]string{"true", "false"}),
				Description:  "Flag for Cisco DNA Center to enable debugging. If not set, it uses the DNAC_DEBUG environment variable; defaults to `false`.",
			},
			"ssl_verify": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				Sensitive:    true,
				DefaultFunc:  schema.EnvDefaultFunc("DNAC_SSL_VERIFY", "true"),
				ValidateFunc: validateStringHasValueFunc([]string{"true", "false"}),
				Description:  "Flag to enable or disable SSL certificate verification. If not set, it uses the DNAC_SSL_VERIFY environment variable; defaults to `true`.",
			},
			"use_api_gateway": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				DefaultFunc:  schema.EnvDefaultFunc("DNAC_USE_API_GATEWAY", "false"),
				ValidateFunc: validateStringHasValueFunc([]string{"true", "false"}),
				Description:  "Flag to enable or disable the usage of the DNAC's API Gateway. If not set, it uses the DNAC_USE_API_GATEWAY environment variable; defaults to `false`.",
			},
			"use_csrf_token": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				DefaultFunc:  schema.EnvDefaultFunc("DNAC_USE_CSRF_TOKEN", "false"),
				ValidateFunc: validateStringHasValueFunc([]string{"true", "false"}),
				Description:  "Flag to enable or disable the usage of the X-CSRF-Token header. If not set, it uses the DNAC_USE_CSRF_TOKEN environment varible; defaults to `false`.",
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"dnacenter_reserve_ip_subpool":                      resourceReserveIPSubpool(),
			"dnacenter_wireless_rf_profile":                     resourceWirelessRfProfile(),
			"dnacenter_wireless_profile":                        resourceWirelessProfile(),
			"dnacenter_configuration_template_project":          resourceConfigurationTemplateProject(),
			"dnacenter_tag":                                     resourceTag(),
			"dnacenter_snmp_properties":                         resourceSNMPProperties(),
			"dnacenter_pnp_global_settings":                     resourcePnpGlobalSettings(),
			"dnacenter_site_design_floormap":                    resourceSiteDesignFloormap(),
			"dnacenter_nfv_profile":                             resourceNfvProfile(),
			"dnacenter_network_device_list":                     resourceNetworkDeviceList(),
			"dnacenter_network_device":                          resourceNetworkDevice(),
			"dnacenter_global_pool":                             resourceGlobalPool(),
			"dnacenter_event_subscription_syslog":               resourceEventSubscriptionSyslog(),
			"dnacenter_event_subscription_rest":                 resourceEventSubscriptionRest(),
			"dnacenter_event_subscription_email":                resourceEventSubscriptionEmail(),
			"dnacenter_event_subscription":                      resourceEventSubscription(),
			"dnacenter_wireless_dynamic_interface":              resourceWirelessDynamicInterface(),
			"dnacenter_wireless_enterprise_ssid":                resourceWirelessEnterpriseSSID(),
			"dnacenter_discovery":                               resourceDiscovery(),
			"dnacenter_device_replacement":                      resourceDeviceReplacement(),
			"dnacenter_reports":                                 resourceReports(),
			"dnacenter_sda_multicast":                           resourceSdaMulticast(),
			"dnacenter_sda_virtual_network_v2":                  resourceSdaVirtualNetworkV2(),
			"dnacenter_sda_provision_device":                    resourceSdaProvisionDevice(),
			"dnacenter_sda_virtual_network_ip_pool":             resourceSdaVirtualNetworkIPPool(),
			"dnacenter_sda_virtual_network":                     resourceSdaVirtualNetwork(),
			"dnacenter_sda_port_assignment_for_user_device":     resourceSdaPortAssignmentForUserDevice(),
			"dnacenter_sda_port_assignment_for_access_point":    resourceSdaPortAssignmentForAccessPoint(),
			"dnacenter_sda_fabric_site":                         resourceSdaFabricSite(),
			"dnacenter_sda_fabric":                              resourceSdaFabric(),
			"dnacenter_sda_fabric_edge_device":                  resourceSdaFabricEdgeDevice(),
			"dnacenter_sda_fabric_control_plane_device":         resourceSdaFabricControlPlaneDevice(),
			"dnacenter_sda_fabric_border_device":                resourceSdaFabricBorderDevice(),
			"dnacenter_sda_fabric_authentication_profile":       resourceSdaFabricAuthenticationProfile(),
			"dnacenter_applications":                            resourceApplications(),
			"dnacenter_application_sets":                        resourceApplicationSets(),
			"dnacenter_pnp_workflow":                            resourcePnpWorkflow(),
			"dnacenter_pnp_device":                              resourcePnpDevice(),
			"dnacenter_configuration_template":                  resourceConfigurationTemplate(),
			"dnacenter_app_policy_queuing_profile":              resourceAppPolicyQueuingProfile(),
			"dnacenter_business_sda_hostonboarding_ssid_ippool": resourceBusinessSdaHostonboardingSSIDIPpool(),
			"dnacenter_endpoint_analytics_profiling_rules":      resourceEndpointAnalyticsProfilingRules(),
			"dnacenter_qos_device_interface":                    resourceQosDeviceInterface(),
			//"dnacenter_app_policy_intent":                       resourceAppPolicyIntent(),
			//"dnacenter_device_credential":                        resourceDeviceCredential(),
			"dnacenter_path_trace":                               resourcePathTrace(),
			"dnacenter_global_credential_cli":                    resourceGlobalCredentialCli(),
			"dnacenter_global_credential_http_read":              resourceGlobalCredentialHTTPRead(),
			"dnacenter_global_credential_http_write":             resourceGlobalCredentialHTTPWrite(),
			"dnacenter_global_credential_netconf":                resourceGlobalCredentialNetconf(),
			"dnacenter_global_credential_snmpv2_read_community":  resourceGlobalCredentialSNMPv2ReadCommunity(),
			"dnacenter_global_credential_snmpv2_write_community": resourceGlobalCredentialSNMPv2WriteCommunity(),
			"dnacenter_global_credential_snmpv3":                 resourceGlobalCredentialSNMPv3(),
			"dnacenter_golden_image":                             resourceGoldenImage(),
			"dnacenter_license_device":                           resourceLicenseDevice(),
			"dnacenter_network":                                  resourceNetwork(),
			"dnacenter_nfv_provision_detail":                     resourceNfvProvisionDetail(),
			"dnacenter_sensor":                                   resourceSensor(),
			"dnacenter_service_provider":                         resourceServiceProvider(),
			"dnacenter_site":                                     resourceSite(),
			//"dnacenter_site_assign":                              resourceSiteAssign(),
			"dnacenter_swim_image_file": resourceSwimImageFile(),
			"dnacenter_swim_image_url":  resourceSwimImageURL(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"dnacenter_reserve_ip_subpool":                             dataSourceReserveIPSubpool(),
			"dnacenter_wireless_rf_profile":                            dataSourceWirelessRfProfile(),
			"dnacenter_wireless_profile":                               dataSourceWirelessProfile(),
			"dnacenter_configuration_template_project":                 dataSourceConfigurationTemplateProject(),
			"dnacenter_tag_member":                                     dataSourceTagMember(),
			"dnacenter_tag":                                            dataSourceTag(),
			"dnacenter_snmp_properties":                                dataSourceSNMPProperties(),
			"dnacenter_site":                                           dataSourceSite(),
			"dnacenter_service_provider":                               dataSourceServiceProvider(),
			"dnacenter_sensor":                                         dataSourceSensor(),
			"dnacenter_pnp_global_settings":                            dataSourcePnpGlobalSettings(),
			"dnacenter_site_design_floormap":                           dataSourceSiteDesignFloormap(),
			"dnacenter_nfv_profile":                                    dataSourceNfvProfile(),
			"dnacenter_network":                                        dataSourceNetwork(),
			"dnacenter_network_device_list":                            dataSourceNetworkDeviceList(),
			"dnacenter_network_device":                                 dataSourceNetworkDevice(),
			"dnacenter_itsm_integration_events_failed":                 dataSourceItsmIntegrationEventsFailed(),
			"dnacenter_global_pool":                                    dataSourceGlobalPool(),
			"dnacenter_path_trace":                                     dataSourcePathTrace(),
			"dnacenter_event_subscription_syslog":                      dataSourceEventSubscriptionSyslog(),
			"dnacenter_event_subscription_rest":                        dataSourceEventSubscriptionRest(),
			"dnacenter_event_subscription_email":                       dataSourceEventSubscriptionEmail(),
			"dnacenter_event_subscription":                             dataSourceEventSubscription(),
			"dnacenter_wireless_dynamic_interface":                     dataSourceWirelessDynamicInterface(),
			"dnacenter_wireless_enterprise_ssid":                       dataSourceWirelessEnterpriseSSID(),
			"dnacenter_discovery":                                      dataSourceDiscovery(),
			"dnacenter_device_replacement":                             dataSourceDeviceReplacement(),
			"dnacenter_device_credential":                              dataSourceDeviceCredential(),
			"dnacenter_reports":                                        dataSourceReports(),
			"dnacenter_sda_multicast":                                  dataSourceSdaMulticast(),
			"dnacenter_sda_virtual_network_v2":                         dataSourceSdaVirtualNetworkV2(),
			"dnacenter_sda_provision_device":                           dataSourceSdaProvisionDevice(),
			"dnacenter_sda_virtual_network_ip_pool":                    dataSourceSdaVirtualNetworkIPPool(),
			"dnacenter_sda_virtual_network":                            dataSourceSdaVirtualNetwork(),
			"dnacenter_sda_port_assignment_for_user_device":            dataSourceSdaPortAssignmentForUserDevice(),
			"dnacenter_sda_port_assignment_for_access_point":           dataSourceSdaPortAssignmentForAccessPoint(),
			"dnacenter_sda_fabric_site":                                dataSourceSdaFabricSite(),
			"dnacenter_sda_fabric":                                     dataSourceSdaFabric(),
			"dnacenter_sda_fabric_edge_device":                         dataSourceSdaFabricEdgeDevice(),
			"dnacenter_sda_fabric_control_plane_device":                dataSourceSdaFabricControlPlaneDevice(),
			"dnacenter_sda_fabric_border_device":                       dataSourceSdaFabricBorderDevice(),
			"dnacenter_sda_fabric_authentication_profile":              dataSourceSdaFabricAuthenticationProfile(),
			"dnacenter_applications":                                   dataSourceApplications(),
			"dnacenter_application_sets":                               dataSourceApplicationSets(),
			"dnacenter_pnp_workflow":                                   dataSourcePnpWorkflow(),
			"dnacenter_pnp_device":                                     dataSourcePnpDevice(),
			"dnacenter_event_artifact_count":                           dataSourceEventArtifactCount(),
			"dnacenter_event_artifact":                                 dataSourceEventArtifact(),
			"dnacenter_user_enrichment_details":                        dataSourceUserEnrichmentDetails(),
			"dnacenter_topology_vlan_details":                          dataSourceTopologyVLANDetails(),
			"dnacenter_topology_site":                                  dataSourceTopologySite(),
			"dnacenter_topology_physical":                              dataSourceTopologyPhysical(),
			"dnacenter_topology_layer_3":                               dataSourceTopologyLayer3(),
			"dnacenter_topology_layer_2":                               dataSourceTopologyLayer2(),
			"dnacenter_configuration_template":                         dataSourceConfigurationTemplate(),
			"dnacenter_configuration_template_version":                 dataSourceConfigurationTemplateVersion(),
			"dnacenter_configuration_template_deploy_status":           dataSourceConfigurationTemplateDeployStatus(),
			"dnacenter_network_device_chassis_details":                 dataSourceNetworkDeviceChassisDetails(),
			"dnacenter_network_device_linecard_details":                dataSourceNetworkDeviceLinecardDetails(),
			"dnacenter_network_device_stack_details":                   dataSourceNetworkDeviceStackDetails(),
			"dnacenter_network_device_supervisor_card_details":         dataSourceNetworkDeviceSupervisorCardDetails(),
			"dnacenter_network_device_inventory_insight_link_mismatch": dataSourceNetworkDeviceInventoryInsightLinkMismatch(),
			"dnacenter_network_device_with_snmp_v3_des":                dataSourceNetworkDeviceWithSNMPV3Des(),
			"dnacenter_network_device_interface_poe":                   dataSourceNetworkDeviceInterfacePoe(),
			"dnacenter_system_health":                                  dataSourceSystemHealth(),
			"dnacenter_system_health_count":                            dataSourceSystemHealthCount(),
			"dnacenter_system_performance":                             dataSourceSystemPerformance(),
			"dnacenter_system_performance_historical":                  dataSourceSystemPerformanceHistorical(),
			"dnacenter_platform_nodes_configuration_summary":           dataSourcePlatformNodesConfigurationSummary(),
			"dnacenter_platform_release_summary":                       dataSourcePlatformReleaseSummary(),
			"dnacenter_task_operation":                                 dataSourceTaskOperation(),
			"dnacenter_task_count":                                     dataSourceTaskCount(),
			"dnacenter_task_tree":                                      dataSourceTaskTree(),
			"dnacenter_task":                                           dataSourceTask(),
			"dnacenter_tag_member_type":                                dataSourceTagMemberType(),
			"dnacenter_tag_count":                                      dataSourceTagCount(),
			"dnacenter_tag_member_count":                               dataSourceTagMemberCount(),
			"dnacenter_site_count":                                     dataSourceSiteCount(),
			"dnacenter_site_health":                                    dataSourceSiteHealth(),
			"dnacenter_security_advisories_per_device":                 dataSourceSecurityAdvisoriesPerDevice(),
			"dnacenter_security_advisories_ids_per_device":             dataSourceSecurityAdvisoriesIDsPerDevice(),
			"dnacenter_security_advisories_summary":                    dataSourceSecurityAdvisoriesSummary(),
			"dnacenter_security_advisories_devices":                    dataSourceSecurityAdvisoriesDevices(),
			"dnacenter_security_advisories":                            dataSourceSecurityAdvisories(),
			"dnacenter_pnp_workflow_count":                             dataSourcePnpWorkflowCount(),
			"dnacenter_pnp_virtual_accounts":                           dataSourcePnpVirtualAccounts(),
			"dnacenter_pnp_smart_account_domains":                      dataSourcePnpSmartAccountDomains(),
			"dnacenter_pnp_virtual_account_sync_result":                dataSourcePnpVirtualAccountSyncResult(),
			"dnacenter_pnp_device_history":                             dataSourcePnpDeviceHistory(),
			"dnacenter_pnp_device_count":                               dataSourcePnpDeviceCount(),
			"dnacenter_topology_network_health":                        dataSourceTopologyNetworkHealth(),
			"dnacenter_network_device_register_for_wsa":                dataSourceNetworkDeviceRegisterForWsa(),
			"dnacenter_network_device_by_serial_number":                dataSourceNetworkDeviceBySerialNumber(),
			"dnacenter_network_device_module_count":                    dataSourceNetworkDeviceModuleCount(),
			"dnacenter_network_device_module":                          dataSourceNetworkDeviceModule(),
			"dnacenter_network_device_by_ip":                           dataSourceNetworkDeviceByIP(),
			"dnacenter_network_device_functional_capability":           dataSourceNetworkDeviceFunctionalCapability(),
			"dnacenter_network_device_count":                           dataSourceNetworkDeviceCount(),
			"dnacenter_network_device_config_count":                    dataSourceNetworkDeviceConfigCount(),
			"dnacenter_network_device_config":                          dataSourceNetworkDeviceConfig(),
			"dnacenter_network_device_global_polling_interval":         dataSourceNetworkDeviceGlobalPollingInterval(),
			"dnacenter_network_device_lexicographically_sorted":        dataSourceNetworkDeviceLexicographicallySorted(),
			"dnacenter_network_device_range":                           dataSourceNetworkDeviceRange(),
			"dnacenter_network_device_wireless_lan":                    dataSourceNetworkDeviceWirelessLan(),
			"dnacenter_network_device_vlan":                            dataSourceNetworkDeviceVLAN(),
			"dnacenter_network_device_meraki_organization":             dataSourceNetworkDeviceMerakiOrganization(),
			"dnacenter_network_device_polling_interval":                dataSourceNetworkDevicePollingInterval(),
			"dnacenter_network_device_summary":                         dataSourceNetworkDeviceSummary(),
			"dnacenter_network_device_poe":                             dataSourceNetworkDevicePoe(),
			"dnacenter_network_device_equipment":                       dataSourceNetworkDeviceEquipment(),
			"dnacenter_dna_command_runner_keywords":                    dataSourceDnaCommandRunnerKeywords(),
			"dnacenter_site_membership":                                dataSourceSiteMembership(),
			"dnacenter_issues":                                         dataSourceIssues(),
			"dnacenter_issues_enrichment_details":                      dataSourceIssuesEnrichmentDetails(),
			"dnacenter_device_interface_ospf":                          dataSourceDeviceInterfaceOspf(),
			"dnacenter_interface_network_device_detail":                dataSourceInterfaceNetworkDeviceDetail(),
			"dnacenter_interface_network_device":                       dataSourceInterfaceNetworkDevice(),
			"dnacenter_interface_network_device_range":                 dataSourceInterfaceNetworkDeviceRange(),
			"dnacenter_device_interface_isis":                          dataSourceDeviceInterfaceIsis(),
			"dnacenter_device_interface_by_ip":                         dataSourceDeviceInterfaceByIP(),
			"dnacenter_device_interface_count":                         dataSourceDeviceInterfaceCount(),
			"dnacenter_device_interface":                               dataSourceDeviceInterface(),
			"dnacenter_swim_image_details":                             dataSourceSwimImageDetails(),
			"dnacenter_global_credential":                              dataSourceGlobalCredential(),
			"dnacenter_file_namespaces":                                dataSourceFileNamespaces(),
			"dnacenter_file_namespace_files":                           dataSourceFileNamespaceFiles(),
			"dnacenter_file":                                           dataSourceFile(),
			"dnacenter_event_count":                                    dataSourceEventCount(),
			"dnacenter_event":                                          dataSourceEvent(),
			"dnacenter_event_subscription_count":                       dataSourceEventSubscriptionCount(),
			"dnacenter_event_subscription_details_syslog":              dataSourceEventSubscriptionDetailsSyslog(),
			"dnacenter_event_subscription_details_rest":                dataSourceEventSubscriptionDetailsRest(),
			"dnacenter_event_subscription_details_email":               dataSourceEventSubscriptionDetailsEmail(),
			"dnacenter_event_series_count":                             dataSourceEventSeriesCount(),
			"dnacenter_event_series":                                   dataSourceEventSeries(),
			"dnacenter_event_api_status":                               dataSourceEventAPIStatus(),
			"dnacenter_discovery_count":                                dataSourceDiscoveryCount(),
			"dnacenter_discovery_range":                                dataSourceDiscoveryRange(),
			"dnacenter_discovery_summary":                              dataSourceDiscoverySummary(),
			"dnacenter_discovery_device_count":                         dataSourceDiscoveryDeviceCount(),
			"dnacenter_discovery_device":                               dataSourceDiscoveryDevice(),
			"dnacenter_discovery_device_range":                         dataSourceDiscoveryDeviceRange(),
			"dnacenter_discovery_job_by_id":                            dataSourceDiscoveryJobByID(),
			"dnacenter_discovery_jobs":                                 dataSourceDiscoveryJobs(),
			"dnacenter_device_replacement_count":                       dataSourceDeviceReplacementCount(),
			"dnacenter_device_health":                                  dataSourceDeviceHealth(),
			"dnacenter_device_enrichment_details":                      dataSourceDeviceEnrichmentDetails(),
			"dnacenter_device_details":                                 dataSourceDeviceDetails(),
			"dnacenter_reports_view_group_view":                        dataSourceReportsViewGroupView(),
			"dnacenter_reports_view_group":                             dataSourceReportsViewGroup(),
			"dnacenter_reports_executions_download":                    dataSourceReportsExecutionsDownload(),
			"dnacenter_reports_executions":                             dataSourceReportsExecutions(),
			"dnacenter_compliance_device_status_count":                 dataSourceComplianceDeviceStatusCount(),
			"dnacenter_compliance_device_details_count":                dataSourceComplianceDeviceDetailsCount(),
			"dnacenter_compliance_device_details":                      dataSourceComplianceDeviceDetails(),
			"dnacenter_compliance_device_by_id_detail":                 dataSourceComplianceDeviceByIDDetail(),
			"dnacenter_compliance_device":                              dataSourceComplianceDevice(),
			"dnacenter_compliance_device_by_id":                        dataSourceComplianceDeviceByID(),
			"dnacenter_itsm_cmdb_sync_status":                          dataSourceItsmCmdbSyncStatus(),
			"dnacenter_client_proximity":                               dataSourceClientProximity(),
			"dnacenter_client_health":                                  dataSourceClientHealth(),
			"dnacenter_client_enrichment_details":                      dataSourceClientEnrichmentDetails(),
			"dnacenter_client_detail":                                  dataSourceClientDetail(),
			"dnacenter_sda_count":                                      dataSourceSdaCount(),
			"dnacenter_sda_device_role":                                dataSourceSdaDeviceRole(),
			"dnacenter_sda_device":                                     dataSourceSdaDevice(),
			"dnacenter_nfv_provision_detail":                           dataSourceNfvProvisionDetail(),
			"dnacenter_wireless_sensor_test_results":                   dataSourceWirelessSensorTestResults(),
			"dnacenter_applications_count":                             dataSourceApplicationsCount(),
			"dnacenter_application_sets_count":                         dataSourceApplicationSetsCount(),
			"dnacenter_applications_health":                            dataSourceApplicationsHealth(),
			"dnacenter_event_series_audit_logs":                        dataSourceEventSeriesAuditLogs(),
			"dnacenter_event_series_audit_logs_summary":                dataSourceEventSeriesAuditLogsSummary(),
			"dnacenter_event_series_audit_logs_parent_records":         dataSourceEventSeriesAuditLogsParentRecords(),
			"dnacenter_license_device_count":                           dataSourceLicenseDeviceCount(),
			"dnacenter_license_device_license_details":                 dataSourceLicenseDeviceLicenseDetails(),
			"dnacenter_license_device_license_summary":                 dataSourceLicenseDeviceLicenseSummary(),
			"dnacenter_license_term_details":                           dataSourceLicenseTermDetails(),
			"dnacenter_license_usage_details":                          dataSourceLicenseUsageDetails(),
			"dnacenter_license_smart_account_details":                  dataSourceLicenseSmartAccountDetails(),
			"dnacenter_license_virtual_account_details":                dataSourceLicenseVirtualAccountDetails(),
			"dnacenter_app_policy":                                     dataSourceAppPolicy(),
			"dnacenter_app_policy_default":                             dataSourceAppPolicyDefault(),
			"dnacenter_app_policy_queuing_profile":                     dataSourceAppPolicyQueuingProfile(),
			"dnacenter_app_policy_queuing_profile_count":               dataSourceAppPolicyQueuingProfileCount(),
			"dnacenter_business_sda_hostonboarding_ssid_ippool":        dataSourceBusinessSdaHostonboardingSSIDIPpool(),
			"dnacenter_disasterrecovery_system_operationstatus":        dataSourceDisasterrecoverySystemOperationstatus(),
			"dnacenter_disasterrecovery_system_status":                 dataSourceDisasterrecoverySystemStatus(),
			"dnacenter_dnacaap_management_execution_status":            dataSourceDnacaapManagementExecutionStatus(),
			"dnacenter_endpoint_analytics_profiling_rules":             dataSourceEndpointAnalyticsProfilingRules(),
			"dnacenter_profiling_rules_count":                          dataSourceProfilingRulesCount(),
			"dnacenter_device_family_identifiers_details":              dataSourceDeviceFamilyIDentifiersDetails(),
			"dnacenter_golden_tag_image_details":                       dataSourceGoldenTagImageDetails(),
			"dnacenter_qos_device_interface":                           dataSourceQosDeviceInterface(),
			"dnacenter_qos_device_interface_info_count":                dataSourceQosDeviceInterfaceInfoCount(),
			"dnacenter_projects_details":                               dataSourceProjectsDetails(),
			"dnacenter_templates_details":                              dataSourceTemplatesDetails(),
		},
		ConfigureContextFunc: providerConfigure,
	}
}
