// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"os"

	dnacentersdkgo "github.com/cisco-en-programmability/dnacenter-go-sdk/v5/sdk"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// terraform-provider-dnacenter
// Ensure DNACenterProvider satisfies various provider interfaces.
var _ provider.Provider = &DNACenterProvider{}

// DNACenterProvider defines the provider implementation.
type DNACenterProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// DNACenterProviderModel describes the provider data model.
type DNACenterProviderModel struct {
	BaseURL   types.String `tfsdk: "base_url"`
	Username  types.String `tfsdk: "username"`
	Password  types.String `tfsdk: "password"`
	Debug     types.String `tfsdk: "debug"`
	SSLVerify types.String `tfsdk: "ssl_verify"`
}

type DNACenterProviderData struct {
	Client *dnacentersdkgo.Client
}

func (p *DNACenterProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "DNACenter"
	resp.Version = p.version
}

func (p *DNACenterProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"base_url": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Cisco DNA Center base URL, FQDN or IP. If not set, it uses the DNAC_BASE_URL environment variable.",
			},
			"username": schema.StringAttribute{
				Optional:            true,
				Sensitive:           true,
				MarkdownDescription: "Cisco DNA Center username to authenticate. If not set, it uses the DNAC_USERNAME environment variable.",
			},
			"password": schema.StringAttribute{
				Optional:            true,
				Sensitive:           true,
				MarkdownDescription: "Cisco DNA Center password to authenticate. If not set, it uses the DNAC_PASSWORD environment variable.",
			},
			"debug": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Flag for Cisco DNA Center to enable debugging. If not set, it uses the DNAC_DEBUG environment variable defaults to `false`.",
			},
			"ssl_verify": schema.StringAttribute{
				Optional:            true,
				Sensitive:           true,
				MarkdownDescription: "Flag to enable or disable SSL certificate verification. If not set, it uses the DNAC_SSL_VERIFY environment variable defaults to `true`.",
			},
		},
	}
}

func (p *DNACenterProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data DNACenterProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if data.BaseURL.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("base_url"),
			"Unknown DNACenter API base_url",
			"The provider cannot create the DNACenter API client as there is an unknown configuration value for the DNACenter API BaseURL. "+
				"Either target apply the source of the value first, set the value statically in the configuration, or use the DNAC_BASE_URL environment variable.",
		)
		return
	}

	if data.Username.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("username"),
			"Unknown DNACenter API username",
			"The provider cannot create the DNACenter API client as there is an unknown configuration value for the DNACenter API Username. "+
				"Either target apply the source of the value first, set the value statically in the configuration, or use the DNAC_USERNAME environment variable.",
		)
		return
	}

	if data.Password.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("password"),
			"Unknown DNACenter API password",
			"The provider cannot create the DNACenter API client as there is an unknown configuration value for the DNACenter API Password. "+
				"Either target apply the source of the value first, set the value statically in the configuration, or use the DNAC_PASSWORD environment variable.",
		)
		return
	}

	if data.Debug.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("debug"),
			"Unknown DNACenter API debug",
			"The provider cannot create the DNACenter API client as there is an unknown configuration value for the DNACenter API Debug. "+
				"Either target apply the source of the value first, set the value statically in the configuration, or use the DNAC_DEBUG environment variable.",
		)
		return
	}
	if data.SSLVerify.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("ssl_verify"),
			"Unknown DNACenter API ssl_verify",
			"The provider cannot create the DNACenter API client as there is an unknown configuration value for the DNACenter API SSLVerify. "+
				"Either target apply the source of the value first, set the value statically in the configuration, or use the DNAC_SSL_VERIFY environment variable.",
		)
		return
	}

	if resp.Diagnostics.HasError() {
		return
	}

	// Default values to enviroment variables, but override
	// with Terraform configuration value if set.
	baseURL := os.Getenv("DNAC_BASE_URL")
	username := os.Getenv("DNAC_USERNAME")
	password := os.Getenv("DNAC_PASSWORD")
	debug := os.Getenv("DNAC_DEBUG")
	sslVerify := os.Getenv("DNAC_SSL_VERIFY")

	if !data.BaseURL.IsNull() {
		baseURL = data.BaseURL.ValueString()
	}
	if !data.Username.IsNull() {
		username = data.Username.ValueString()
	}
	if !data.Password.IsNull() {
		password = data.Password.ValueString()
	}
	if !data.Debug.IsNull() {
		debug = data.Debug.ValueString()
	}
	if !data.SSLVerify.IsNull() {
		sslVerify = data.SSLVerify.ValueString()
	}

	// Create a new DNACenter client using the configuration values
	client, err := dnacentersdkgo.NewClientWithOptions(baseURL,
		username, password,
		debug, sslVerify, nil,
	)
	if err != nil {
		resp.Diagnostics.AddError(
			"Uneable to Create DNACenter API Client",
			"Error: "+err.Error(),
		)
		return
	}
	client.RestyClient().SetLogger(createLogger())
	dataClient := DNACenterProviderData{Client: client}

	resp.DataSourceData = dataClient
	resp.ResourceData = dataClient

}

func (p *DNACenterProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		// NewReserveIPSubpoolResource,
		// NewWirelessRfProfileResource,
		// NewWirelessProfileResource,
		// NewConfigurationTemplateProjectResource,
		// NewTagResource,
		// NewSNMPPropertiesResource,
		// NewPnpGlobalSettingsResource,
		// NewNfvProfileResource,
		// NewNetworkDeviceListResource,
		// NewNetworkDeviceResource,
		// NewGlobalPoolResource,
		// NewPathTraceResource,
		// NewTransitPeerNetworkResource,
		// NewEventSubscriptionSyslogResource,
		// NewEventSubscriptionRestResource,
		// NewEventSubscriptionEmailResource,
		// NewEventSubscriptionResource,
		// NewWirelessDynamicInterfaceResource,
		// NewWirelessEnterpriseSSIDResource,
		// NewDiscoveryResource,
		// NewDeviceReplacementResource,
		// NewReportsResource,
		// NewSdaMulticastResource,
		// NewSdaVirtualNetworkV2Resource,
		// NewSdaProvisionDeviceResource,
		// NewSdaVirtualNetworkIPPoolResource,
		// NewSdaVirtualNetworkResource,
		// NewSdaPortAssignmentForUserDeviceResource,
		// NewSdaPortAssignmentForAccessPointResource,
		// NewSdaFabricSiteResource,
		// NewSdaFabricEdgeDeviceResource,
		// NewSdaFabricControlPlaneDeviceResource,
		// NewSdaFabricBorderDeviceResource,
		// NewSdaFabricAuthenticationProfileResource,
		// NewApplicationsResource,
		// NewApplicationSetsResource,
		// NewPnpWorkflowResource,
		// NewPnpDeviceResource,
		// NewConfigurationTemplateResource,
		// NewAppPolicyQueuingProfileResource,
		// NewBusinessSdaHostonboardingSSIDIPpoolResource,
		// NewQosDeviceInterfaceResource,
		// NewNetworkDeviceCustomPromptResource,
		// NewAreaResource,
		// NewBuildingResource,
		// NewFloorResource,
		// NewServiceProviderResource,
		// NewSensorResource,
		// NewDeployTemplateResource,
		// NewNfvProvisionDetailResource,
		// NewLicenseDeviceResource,
		// NewGoldenTagImageResource,
		// NewDeviceRebootAprebootResource,
		// NewEventEmailConfigResource,
		// NewEventSyslogConfigResource,
		// NewIntegrationSettingsInstancesItsmResource,
		// NewNetworkDeviceUserDefinedFieldResource,
		// NewGlobalCredentialV2Resource,
		// NewNetworkV2Resource,
		// NewServiceProviderV2Resource,
		// NewUserResource,
		// NewSiteAssignCredentialResource,
		// NewWirelessProvisionDeviceCreateResource,
		// NewWirelessProvisionDeviceUpdateResource,
		// NewWirelessProvisionAccessPointResource,
		// NewTemplatePreviewResource,
		// NewSensorTestTemplateDuplicateResource,
		// NewSensorTestRunResource,
		// NewPnpVirtualAccountDeregisterResource,
		// NewPnpServerProfileUpdateResource,
		// NewPnpVirtualAccountAddResource,
		// NewPnpVirtualAccountDevicesSyncResource,
		// NewPnpDeviceUnclaimResource,
		// NewPnpDeviceConfigPreviewResource,
		// NewPnpDeviceSiteClaimResource,
		// NewPnpDeviceResetResource,
		// NewPnpDeviceImportResource,
		// NewPnpDeviceClaimResource,
		// NewNetworkCreateResource,
		// NewNetworkUpdateResource,
		// NewNetworkDeviceSyncResource,
		// NewNetworkDeviceExportResource,
		// NewNetworkDeviceUpdateRoleResource,
		// NewCommandRunnerRunCommandResource,
		// NewDeviceConfigurationsExportResource,
		// NewItsmIntegrationEventsRetryResource,
		// NewSwimImageURLResource,
		// NewSwimImageFileResource,
		// NewImageDistributionResource,
		// NewImageDeviceActivationResource,
		// NewGlobalCredentialUpdateResource,
		// NewGlobalCredentialDeleteResource,
		// NewDiscoveryRangeDeleteResource,
		// NewDeviceReplacementDeployResource,
		// NewComplianceResource,
		// NewWirelessProvisionSSIDDeleteReprovisionResource,
		// NewWirelessProvisionSSIDCreateProvisionResource,
		// NewNfvProvisionResource,
		// NewSensorTestTemplateEditResource,
		// NewConfigurationTemplateCloneResource,
		// NewConfigurationTemplateExportProjectResource,
		// NewConfigurationTemplateExportTemplateResource,
		// NewConfigurationTemplateImportProjectResource,
		// NewConfigurationTemplateImportTemplateResource,
		// NewAppPolicyIntentCreateResource,
		// NewBusinessSdaWirelessControllerCreateResource,
		// NewBusinessSdaWirelessControllerDeleteResource,
		// NewAssignDeviceToSiteResource,
		// NewAssociateSiteToNetworkProfileResource,
		// NewPnpDeviceAuthorizeResource,
		// NewDisassociateSiteToNetworkProfileResource,
		// NewEventEmailConfigCreateResource,
		// NewEventEmailConfigUpdateResource,
		// NewInterfaceUpdateResource,
		// NewInterfaceOperationCreateResource,
		// NewLanAutomationCreateResource,
		// NewLanAutomationDeleteResource,
		// NewEventWebhookUpdateResource,
		// NewSyslogConfigUpdateResource,
		// NewEventWebhookCreateResource,
		// NewSyslogConfigCreateResource,
		// NewFileImportResource,
		// NewExecuteSuggestedActionsCommandsResource,
		// NewWirelessAccespointConfigurationResource,
		// NewCredentialToSiteBySiteidCreateV2Resource,
		// NewSpProfileDeleteV2Resource,
		// NewSensorTestDeleteResource,
		// NewSensorTestCreateResource,
		// NewGoldenImageResource,
		// NewDeployTemplateV1Resource,
		// NewGlobalCredentialSNMPv3Resource,
		// NewGlobalCredentialSNMPv2WriteCommunityResource,
		// NewGlobalCredentialSNMPv2ReadCommunityResource,
		// NewGlobalCredentialNetconfResource,
		// NewGlobalCredentialHTTPWriteResource,
		// NewGlobalCredentialHTTPReadResource,
		// NewGlobalCredentialCliResource,
		// NewTagMembershipResource,
		// NewConfigurationTemplateVersionResource,
	}
}

func (p *DNACenterProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		// NewReserveIPSubpoolDataSource,
		// NewWirelessRfProfileDataSource,
		// NewWirelessProfileDataSource,
		// NewConfigurationTemplateProjectDataSource,
		// NewTagDataSource,
		// NewSNMPPropertiesDataSource,
		// NewPnpGlobalSettingsDataSource,
		// NewNfvProfileDataSource,
		// NewNetworkDeviceListDataSource,
		// NewNetworkDeviceDataSource,
		// NewGlobalPoolDataSource,
		// NewPathTraceDataSource,
		// NewTransitPeerNetworkDataSource,
		// NewBusinessSdaVirtualNetworkSummaryDataSource,
		// NewEventSubscriptionSyslogDataSource,
		// NewEventSubscriptionRestDataSource,
		// NewEventSubscriptionEmailDataSource,
		// NewEventSubscriptionDataSource,
		// NewWirelessDynamicInterfaceDataSource,
		// NewWirelessEnterpriseSSIDDataSource,
		// NewDiscoveryDataSource,
		// NewDeviceReplacementDataSource,
		// NewReportsDataSource,
		// NewSdaMulticastDataSource,
		// NewSdaVirtualNetworkV2DataSource,
		// NewSdaProvisionDeviceDataSource,
		// NewSdaVirtualNetworkIPPoolDataSource,
		// NewSdaVirtualNetworkDataSource,
		// NewSdaPortAssignmentForUserDeviceDataSource,
		// NewSdaPortAssignmentForAccessPointDataSource,
		// NewSdaFabricSiteDataSource,
		// NewSdaFabricEdgeDeviceDataSource,
		// NewSdaFabricControlPlaneDeviceDataSource,
		// NewSdaFabricBorderDeviceDataSource,
		// NewSdaFabricAuthenticationProfileDataSource,
		// NewApplicationsDataSource,
		// NewApplicationSetsDataSource,
		// NewPnpWorkflowDataSource,
		// NewPnpDeviceDataSource,
		// NewConfigurationTemplateDataSource,
		// NewAppPolicyQueuingProfileDataSource,
		// NewBusinessSdaHostonboardingSSIDIPpoolDataSource,
		// NewQosDeviceInterfaceDataSource,
		// NewNetworkDeviceCustomPromptDataSource,
		// NewTagMemberDataSource,
		// NewSiteDataSource,
		// NewServiceProviderDataSource,
		// NewSensorDataSource,
		// NewNetworkDataSource,
		// NewItsmIntegrationEventsFailedDataSource,
		// NewDeviceCredentialDataSource,
		// NewEventArtifactCountDataSource,
		// NewEventArtifactDataSource,
		// NewUserEnrichmentDetailsDataSource,
		// NewTopologyVLANDetailsDataSource,
		// NewTopologySiteDataSource,
		// NewTopologyPhysicalDataSource,
		// NewTopologyLayer3DataSource,
		// NewTopologyLayer2DataSource,
		// NewConfigurationTemplateVersionDataSource,
		// NewConfigurationTemplateDeployStatusDataSource,
		// NewDeployTemplateDataSource,
		// NewNetworkDeviceChassisDetailsDataSource,
		// NewNetworkDeviceLinecardDetailsDataSource,
		// NewNetworkDeviceStackDetailsDataSource,
		// NewNetworkDeviceSupervisorCardDetailsDataSource,
		// NewNetworkDeviceInventoryInsightLinkMismatchDataSource,
		// NewNetworkDeviceWithSNMPV3DesDataSource,
		// NewNetworkDeviceInterfacePoeDataSource,
		// NewSystemHealthDataSource,
		// NewSystemHealthCountDataSource,
		// NewSystemPerformanceDataSource,
		// NewSystemPerformanceHistoricalDataSource,
		// NewPlatformNodesConfigurationSummaryDataSource,
		// NewPlatformReleaseSummaryDataSource,
		// NewTaskOperationDataSource,
		// NewTaskCountDataSource,
		// NewTaskTreeDataSource,
		// NewTaskDataSource,
		// NewTagMemberTypeDataSource,
		// NewTagCountDataSource,
		// NewTagMemberCountDataSource,
		// NewSiteCountDataSource,
		// NewSiteHealthDataSource,
		// NewSecurityAdvisoriesPerDeviceDataSource,
		// NewSecurityAdvisoriesIDsPerDeviceDataSource,
		// NewSecurityAdvisoriesSummaryDataSource,
		// NewSecurityAdvisoriesDevicesDataSource,
		// NewSecurityAdvisoriesDataSource,
		// NewPnpWorkflowCountDataSource,
		// NewPnpVirtualAccountsDataSource,
		// NewPnpSmartAccountDomainsDataSource,
		// NewPnpVirtualAccountSyncResultDataSource,
		// NewPnpDeviceHistoryDataSource,
		// NewPnpDeviceCountDataSource,
		// NewTopologyNetworkHealthDataSource,
		// NewNetworkDeviceRegisterForWsaDataSource,
		// NewNetworkDeviceBySerialNumberDataSource,
		// NewNetworkDeviceModuleCountDataSource,
		// NewNetworkDeviceModuleDataSource,
		// NewNetworkDeviceByIPDataSource,
		// NewNetworkDeviceFunctionalCapabilityDataSource,
		// NewNetworkDeviceCountDataSource,
		// NewNetworkDeviceConfigCountDataSource,
		// NewNetworkDeviceConfigDataSource,
		// NewNetworkDeviceGlobalPollingIntervalDataSource,
		// NewNetworkDeviceLexicographicallySortedDataSource,
		// NewNetworkDeviceRangeDataSource,
		// NewNetworkDeviceWirelessLanDataSource,
		// NewNetworkDeviceVLANDataSource,
		// NewNetworkDeviceMerakiOrganizationDataSource,
		// NewNetworkDevicePollingIntervalDataSource,
		// NewNetworkDeviceSummaryDataSource,
		// NewNetworkDevicePoeDataSource,
		// NewNetworkDeviceEquipmentDataSource,
		// NewDnaCommandRunnerKeywordsDataSource,
		// NewSiteMembershipDataSource,
		// NewIssuesDataSource,
		// NewIssuesEnrichmentDetailsDataSource,
		// NewDeviceInterfaceOspfDataSource,
		// NewInterfaceNetworkDeviceDetailDataSource,
		// NewInterfaceNetworkDeviceDataSource,
		// NewInterfaceNetworkDeviceRangeDataSource,
		// NewDeviceInterfaceIsisDataSource,
		// NewDeviceInterfaceByIPDataSource,
		// NewDeviceInterfaceCountDataSource,
		// NewDeviceInterfaceDataSource,
		// NewSwimImageDetailsDataSource,
		// NewGlobalCredentialDataSource,
		// NewFileNamespacesDataSource,
		// NewFileNamespaceFilesDataSource,
		// NewFileDataSource,
		// NewEventCountDataSource,
		// NewEventDataSource,
		// NewEventSubscriptionCountDataSource,
		// NewEventSubscriptionDetailsSyslogDataSource,
		// NewEventSubscriptionDetailsRestDataSource,
		// NewEventSubscriptionDetailsEmailDataSource,
		// NewEventSeriesCountDataSource,
		// NewEventSeriesDataSource,
		// NewEventAPIStatusDataSource,
		// NewDiscoveryCountDataSource,
		// NewDiscoveryRangeDataSource,
		// NewDiscoverySummaryDataSource,
		// NewDiscoveryDeviceCountDataSource,
		// NewDiscoveryDeviceDataSource,
		// NewDiscoveryDeviceRangeDataSource,
		// NewDiscoveryJobByIDDataSource,
		// NewDiscoveryJobsDataSource,
		// NewDeviceReplacementCountDataSource,
		// NewDeviceHealthDataSource,
		// NewDeviceEnrichmentDetailsDataSource,
		// NewDeviceDetailsDataSource,
		// NewReportsViewGroupViewDataSource,
		// NewReportsViewGroupDataSource,
		// NewReportsExecutionsDownloadDataSource,
		// NewReportsExecutionsDataSource,
		// NewComplianceDeviceStatusCountDataSource,
		// NewComplianceDeviceDetailsCountDataSource,
		// NewComplianceDeviceDetailsDataSource,
		// NewComplianceDeviceByIDDetailDataSource,
		// NewComplianceDeviceDataSource,
		// NewComplianceDeviceByIDDataSource,
		// NewItsmCmdbSyncStatusDataSource,
		// NewClientProximityDataSource,
		// NewClientHealthDataSource,
		// NewClientEnrichmentDetailsDataSource,
		// NewClientDetailDataSource,
		// NewSdaDeviceRoleDataSource,
		// NewSdaDeviceDataSource,
		// NewNfvProvisionDetailDataSource,
		// NewWirelessSensorTestResultsDataSource,
		// NewApplicationsCountDataSource,
		// NewApplicationSetsCountDataSource,
		// NewApplicationsHealthDataSource,
		// NewEventSeriesAuditLogsDataSource,
		// NewEventSeriesAuditLogsSummaryDataSource,
		// NewEventSeriesAuditLogsParentRecordsDataSource,
		// NewLicenseDeviceCountDataSource,
		// NewLicenseDeviceLicenseDetailsDataSource,
		// NewLicenseDeviceLicenseSummaryDataSource,
		// NewLicenseTermDetailsDataSource,
		// NewLicenseUsageDetailsDataSource,
		// NewLicenseDeviceDataSource,
		// NewLicenseVirtualAccountDetailsDataSource,
		// NewAppPolicyDataSource,
		// NewAppPolicyDefaultDataSource,
		// NewAppPolicyQueuingProfileCountDataSource,
		// NewDnacaapManagementExecutionStatusDataSource,
		// NewDeviceFamilyIDentifiersDetailsDataSource,
		// NewGoldenTagImageDataSource,
		// NewQosDeviceInterfaceInfoCountDataSource,
		// NewProjectsDetailsDataSource,
		// NewTemplatesDetailsDataSource,
		// NewNetworkDeviceInterfaceNeighborDataSource,
		// NewLanAutomationLogDataSource,
		// NewBuildingsPlannedAccessPointsDataSource,
		// NewLanAutomationStatusDataSource,
		// NewInterfaceDataSource,
		// NewEventConfigConnectorTypesDataSource,
		// NewLanAutomationCountDataSource,
		// NewPlannedAccessPointsDataSource,
		// NewAuthenticationPolicyServersDataSource,
		// NewDeviceRebootAprebootDataSource,
		// NewDnacPackagesDataSource,
		// NewEoxStatusDeviceDataSource,
		// NewEoxStatusSummaryDataSource,
		// NewEventEmailConfigDataSource,
		// NewEventSNMPConfigDataSource,
		// NewEventSyslogConfigDataSource,
		// NewIntegrationSettingsInstancesItsmDataSource,
		// NewLanAutomationLogBySerialNumberDataSource,
		// NewNetworkDeviceUserDefinedFieldDataSource,
		// NewAccesspointConfigurationDetailsByTaskIDDataSource,
		// NewWirelessAccesspointConfigurationSummaryDataSource,
		// NewGlobalCredentialV2DataSource,
		// NewNetworkV2DataSource,
		// NewServiceProviderV2DataSource,
		// NewRolePermissionsDataSource,
		// NewRolesDataSource,
		// NewUserDataSource,
		// NewUsersExternalServersDataSource,
		// NewLicenseSmartAccountDetailsDataSource,
		// NewGoldenTagImageDetailsDataSource,
	}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &DNACenterProvider{
			version: version,
		}
	}
}
