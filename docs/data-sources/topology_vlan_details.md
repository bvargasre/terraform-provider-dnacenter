---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "dnacenter_topology_vlan_details Data Source - terraform-provider-dnacenter"
subcategory: ""
description: |-
  It performs read operation on Topology.
  Returns the list of VLAN names
---

# dnacenter_topology_vlan_details (Data Source)

It performs read operation on Topology.

- Returns the list of VLAN names

## Example Usage

```terraform
data "dnacenter_topology_vlan_details" "example" {
  provider = dnacenter
}

output "dnacenter_topology_vlan_details_example" {
  value = data.dnacenter_topology_vlan_details.example.items
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- **id** (String) The ID of this resource.

### Read-Only

- **items** (List of Object) (see [below for nested schema](#nestedatt--items))

<a id="nestedatt--items"></a>
### Nested Schema for `items`

Read-Only:

- **response** (List of String)
- **version** (String)

