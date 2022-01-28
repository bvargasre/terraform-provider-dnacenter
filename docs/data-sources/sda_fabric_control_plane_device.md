---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "dnacenter_sda_fabric_control_plane_device Data Source - terraform-provider-dnacenter"
subcategory: ""
description: |-
  It performs read operation on SDA.
  Get control plane device from SDA Fabric
---

# dnacenter_sda_fabric_control_plane_device (Data Source)

It performs read operation on SDA.

- Get control plane device from SDA Fabric

## Example Usage

```terraform
data "dnacenter_sda_fabric_control_plane_device" "example" {
  provider                     = dnacenter
  device_management_ip_address = "string"
}

output "dnacenter_sda_fabric_control_plane_device_example" {
  value = data.dnacenter_sda_fabric_control_plane_device.example.item
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- **device_management_ip_address** (String) deviceManagementIpAddress query parameter.

### Optional

- **id** (String) The ID of this resource.

### Read-Only

- **item** (List of Object) (see [below for nested schema](#nestedatt--item))

<a id="nestedatt--item"></a>
### Nested Schema for `item`

Read-Only:

- **description** (String)
- **device_management_ip_address** (String)
- **name** (String)
- **roles** (List of String)
- **site_hierarchy** (String)
- **status** (String)

