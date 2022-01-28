---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "dnacenter_wireless_profile Resource - terraform-provider-dnacenter"
subcategory: ""
description: |-
  It manages create, read, update and delete operations on Wireless.
  Delete the Wireless Profile from DNAC whose name is provided.Updates the wireless Network Profile with updated details provided. All sites to be present in the network profile
  should be provided.Creates Wireless Network Profile on DNAC and associates sites and SSIDs to it.
---

# dnacenter_wireless_profile (Resource)

It manages create, read, update and delete operations on Wireless.

- Delete the Wireless Profile from DNAC whose name is provided.

- Updates the wireless Network Profile with updated details provided. All sites to be present in the network profile
should be provided.

- Creates Wireless Network Profile on DNAC and associates sites and SSIDs to it.

## Example Usage

```terraform
resource "dnacenter_wireless_profile" "example" {
  provider = dnacenter
  parameters {

    profile_details {

      name  = "string"
      sites = ["string"]
      ssid_details {

        enable_fabric = "false"
        flex_connect {

          enable_flex_connect = "false"
          local_to_vlan       = 1
        }
        interface_name = "string"
        name           = "string"
        type           = "string"
      }
    }
    wireless_profile_name = "string"
  }
}

output "dnacenter_wireless_profile_example" {
  value = dnacenter_wireless_profile.example
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- **parameters** (Block List, Min: 1, Max: 1) (see [below for nested schema](#nestedblock--parameters))

### Optional

- **id** (String) The ID of this resource.

### Read-Only

- **item** (List of Object) (see [below for nested schema](#nestedatt--item))
- **last_updated** (String)

<a id="nestedblock--parameters"></a>
### Nested Schema for `parameters`

Required:

- **profile_details** (Block List, Min: 1, Max: 1) (see [below for nested schema](#nestedblock--parameters--profile_details))

Optional:

- **wireless_profile_name** (String) wirelessProfileName path parameter. Wireless Profile Name

<a id="nestedblock--parameters--profile_details"></a>
### Nested Schema for `parameters.profile_details`

Required:

- **name** (String) Profile Name

Optional:

- **sites** (List of String) array of site name hierarchies(eg: ["Global/aaa/zzz", "Global/aaa/zzz"])
- **ssid_details** (Block List, Max: 1) (see [below for nested schema](#nestedblock--parameters--profile_details--ssid_details))

<a id="nestedblock--parameters--profile_details--ssid_details"></a>
### Nested Schema for `parameters.profile_details.ssid_details`

Optional:

- **enable_fabric** (String) true is ssid is fabric else false
- **flex_connect** (Block List, Max: 1) (see [below for nested schema](#nestedblock--parameters--profile_details--ssid_details--flex_connect))
- **interface_name** (String) Interface Name
- **name** (String) Ssid Name
- **type** (String) Ssid Type(enum: Enterprise/Guest)

<a id="nestedblock--parameters--profile_details--ssid_details--flex_connect"></a>
### Nested Schema for `parameters.profile_details.ssid_details.type`

Optional:

- **enable_flex_connect** (String) true if flex connect is enabled else false
- **local_to_vlan** (Number) Local To Vlan





<a id="nestedatt--item"></a>
### Nested Schema for `item`

Read-Only:

- **profile_details** (List of Object) (see [below for nested schema](#nestedobjatt--item--profile_details))

<a id="nestedobjatt--item--profile_details"></a>
### Nested Schema for `item.profile_details`

Read-Only:

- **name** (String)
- **sites** (List of String)
- **ssid_details** (List of Object) (see [below for nested schema](#nestedobjatt--item--profile_details--ssid_details))

<a id="nestedobjatt--item--profile_details--ssid_details"></a>
### Nested Schema for `item.profile_details.ssid_details`

Read-Only:

- **enable_fabric** (String)
- **flex_connect** (List of Object) (see [below for nested schema](#nestedobjatt--item--profile_details--ssid_details--flex_connect))
- **interface_name** (String)
- **name** (String)
- **type** (String)

<a id="nestedobjatt--item--profile_details--ssid_details--flex_connect"></a>
### Nested Schema for `item.profile_details.ssid_details.type`

Read-Only:

- **enable_flex_connect** (String)
- **local_to_vlan** (Number)

## Import

Import is supported using the following syntax:

```shell
terraform import dnacenter_wireless_profile.example "id:=string"
```