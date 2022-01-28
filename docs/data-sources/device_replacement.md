---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "dnacenter_device_replacement Data Source - terraform-provider-dnacenter"
subcategory: ""
description: |-
  It performs read operation on Device Replacement.
  Get list of replacement devices with replacement details and it can filter replacement devices based on Faulty Device
  Name,Faulty Device Platform, Replacement Device Platform, Faulty Device Serial Number,Replacement Device Serial Number,
  Device Replacement status, Product Family.
---

# dnacenter_device_replacement (Data Source)

It performs read operation on Device Replacement.

- Get list of replacement devices with replacement details and it can filter replacement devices based on Faulty Device
Name,Faulty Device Platform, Replacement Device Platform, Faulty Device Serial Number,Replacement Device Serial Number,
Device Replacement status, Product Family.

## Example Usage

```terraform
data "dnacenter_device_replacement" "example" {
  provider                         = dnacenter
  family                           = ["string"]
  faulty_device_name               = "string"
  faulty_device_platform           = "string"
  faulty_device_serial_number      = "string"
  limit                            = 1
  offset                           = 1
  replacement_device_platform      = "string"
  replacement_device_serial_number = "string"
  replacement_status               = ["string"]
  sort_by                          = "string"
  sort_order                       = "string"
}

output "dnacenter_device_replacement_example" {
  value = data.dnacenter_device_replacement.example.items
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- **family** (List of String) family query parameter. List of families[Routers, Switches and Hubs, AP]
- **faulty_device_name** (String) faultyDeviceName query parameter. Faulty Device Name
- **faulty_device_platform** (String) faultyDevicePlatform query parameter. Faulty Device Platform
- **faulty_device_serial_number** (String) faultyDeviceSerialNumber query parameter. Faulty Device Serial Number
- **id** (String) The ID of this resource.
- **limit** (Number) limit query parameter.
- **offset** (Number) offset query parameter.
- **replacement_device_platform** (String) replacementDevicePlatform query parameter. Replacement Device Platform
- **replacement_device_serial_number** (String) replacementDeviceSerialNumber query parameter. Replacement Device Serial Number
- **replacement_status** (List of String) replacementStatus query parameter. Device Replacement status [READY-FOR-REPLACEMENT, REPLACEMENT-IN-PROGRESS, REPLACEMENT-SCHEDULED, REPLACED, ERROR, NETWORK_READINESS_REQUESTED, NETWORK_READINESS_FAILED]
- **sort_by** (String) sortBy query parameter. SortBy this field. SortBy is mandatory when order is used.
- **sort_order** (String) sortOrder query parameter. Order on displayName[ASC,DESC]

### Read-Only

- **items** (List of Object) (see [below for nested schema](#nestedatt--items))

<a id="nestedatt--items"></a>
### Nested Schema for `items`

Read-Only:

- **creation_time** (Number)
- **family** (String)
- **faulty_device_id** (String)
- **faulty_device_name** (String)
- **faulty_device_platform** (String)
- **faulty_device_serial_number** (String)
- **id** (String)
- **neighbour_device_id** (String)
- **network_readiness_task_id** (String)
- **replacement_device_platform** (String)
- **replacement_device_serial_number** (String)
- **replacement_status** (String)
- **replacement_time** (Number)
- **workflow_id** (String)

