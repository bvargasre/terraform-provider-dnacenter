package dnacenter

import (
	"context"
	"time"

	"log"

	dnacentersdkgo "dnacenter-go-sdk/sdk"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceWirelessProvisionSsidDeleteReprovision() *schema.Resource {
	return &schema.Resource{
		Description: `It performs delete operation on Wireless.
		- Removes SSID or WLAN from the network profile, reprovision the device(s) and deletes the SSID or WLAN from DNA Center
	
`,

		CreateContext: resourceWirelessProvisionSsidDeleteReprovisionCreate,
		ReadContext:   resourceWirelessProvisionSsidDeleteReprovisionRead,
		DeleteContext: resourceWirelessProvisionSsidDeleteReprovisionDelete,

		Schema: map[string]*schema.Schema{
			"last_updated": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},
			"item": &schema.Schema{
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{

						"execution_id": &schema.Schema{
							Description: `Execution Id`,
							Type:        schema.TypeString,
							Computed:    true,
						},
						"execution_status_url": &schema.Schema{
							Description: `Execution Status Url`,
							Type:        schema.TypeString,
							Computed:    true,
						},
						"message": &schema.Schema{
							Description: `Message`,
							Type:        schema.TypeString,
							Computed:    true,
						},
					},
				},
			},
			"parameters": &schema.Schema{
				Type:     schema.TypeList,
				Required: true,
				MaxItems: 1,
				MinItems: 1,
				ForceNew: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"managed_aplocations": &schema.Schema{
							Description: `managedAPLocations path parameter.`,
							Type:        schema.TypeString,
							Required:    true,
							ForceNew:    true,
						},
						"ssid_name": &schema.Schema{
							Description: `ssidName path parameter.`,
							Type:        schema.TypeString,
							Required:    true,
							ForceNew:    true,
						},
						"persistbapioutput": &schema.Schema{
							Description: `__persistbapioutput header parameter. Persist bapi sync response
						`,
							Type:         schema.TypeString,
							ValidateFunc: validateStringHasValueFunc([]string{"", "true", "false"}),
							Optional:     true,
							ForceNew:     true,
						},
					},
				},
			},
		},
	}
}

func resourceWirelessProvisionSsidDeleteReprovisionCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*dnacentersdkgo.Client)
	resourceItem := *getResourceItem(d.Get("parameters"))
	vSSIDName := resourceItem["ssid_name"]
	vvSSIDName := interfaceToString(vSSIDName)
	vManagedApLocations := resourceItem["managed_aplocations"]
	vvManagedApLocations := interfaceToString(vManagedApLocations)
	vPersistbapioutput, okPersistbapioutput := d.GetOk("persistbapioutput")
	var diags diag.Diagnostics

	log.Printf("[DEBUG] Selected method 1: DeleteSSIDAndProvisionItToDevices")
	headerParams1 := dnacentersdkgo.DeleteSSIDAndProvisionItToDevicesHeaderParams{}

	if okPersistbapioutput {
		headerParams1.Persistbapioutput = vPersistbapioutput.(string)
	}

	response1, restyResp1, err := client.Wireless.DeleteSSIDAndProvisionItToDevices(vvSSIDName, vvManagedApLocations, &headerParams1)
	if err != nil || response1 == nil {
		if restyResp1 != nil {
			log.Printf("[DEBUG] Retrieved error response %s", restyResp1.String())
		}
		diags = append(diags, diagErrorWithAlt(
			"Failure when executing DeleteSSIDAndProvisionItToDevices", err,
			"Failure at DeleteSSIDAndProvisionItToDevices, unexpected response", ""))
		return diags
	}

	executionId := response1.ExecutionID
	log.Printf("[DEBUG] ExecutionID => %s", executionId)
	if executionId != "" {
		time.Sleep(5 * time.Second)
		response2, restyResp2, err := client.Task.GetBusinessAPIExecutionDetails(executionId)
		if err != nil || response2 == nil {
			if restyResp2 != nil {
				log.Printf("[DEBUG] Retrieved error response %s", restyResp2.String())
			}
			diags = append(diags, diagErrorWithAlt(
				"Failure when executing GetBusinessAPIExecutionDetails", err,
				"Failure at GetBusinessAPIExecutionDetails, unexpected response", ""))
			return diags
		}
		for response2.Status == "IN_PROGRESS" {
			time.Sleep(10 * time.Second)
			response2, restyResp1, err = client.Task.GetBusinessAPIExecutionDetails(executionId)
			if err != nil || response2 == nil {
				if restyResp1 != nil {
					log.Printf("[DEBUG] Retrieved error response %s", restyResp1.String())
				}
				diags = append(diags, diagErrorWithAlt(
					"Failure when executing GetExecutionByID", err,
					"Failure at GetExecutionByID, unexpected response", ""))
				return diags
			}
		}
		if response2.Status == "FAILURE" {
			bapiError := response2.BapiError
			diags = append(diags, diagErrorWithAlt(
				"Failure when executing DeleteSSIDAndProvisionItToDevices", err,
				"Failure at DeleteSSIDAndProvisionItToDevices execution", bapiError))
			return diags
		}
	}

	log.Printf("[DEBUG] Retrieved response %+v", responseInterfaceToString(*response1))
	vItem1 := flattenWirelessDeleteSSIDAndProvisionItToDevicesItem(response1)
	if err := d.Set("item", vItem1); err != nil {
		diags = append(diags, diagError(
			"Failure when setting DeleteSSIDAndProvisionItToDevices response",
			err))
		return diags
	}
	log.Printf("[DEBUG] Retrieved error response %s", restyResp1.String())
	d.SetId(getUnixTimeString())
	return resourceWirelessProvisionSsidDeleteReprovisionRead(ctx, d, m)
}

func resourceWirelessProvisionSsidDeleteReprovisionRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	//client := m.(*dnacentersdkgo.Client)

	var diags diag.Diagnostics

	return diags
}

func resourceWirelessProvisionSsidDeleteReprovisionDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {

	//client := m.(*dnacentersdkgo.Client)

	var diags diag.Diagnostics
	return diags
}

func flattenWirelessDeleteSSIDAndProvisionItToDevicesItem(item *dnacentersdkgo.ResponseWirelessDeleteSSIDAndProvisionItToDevices) []map[string]interface{} {
	if item == nil {
		return nil
	}
	respItem := make(map[string]interface{})
	respItem["execution_id"] = item.ExecutionID
	respItem["execution_status_url"] = item.ExecutionStatusURL
	respItem["message"] = item.Message
	return []map[string]interface{}{
		respItem,
	}
}
