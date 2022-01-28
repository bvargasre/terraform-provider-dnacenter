---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "dnacenter_sda_fabric_site Resource - terraform-provider-dnacenter"
subcategory: ""
description: |-
  It manages create, read and delete operations on SDA.
  Delete Site from SDA FabricAdd Site in SDA Fabric
---

# dnacenter_sda_fabric_site (Resource)

It manages create, read and delete operations on SDA.

- Delete Site from SDA Fabric

- Add Site in SDA Fabric

## Example Usage

```terraform
resource "dnacenter_sda_fabric_site" "example" {
  provider = dnacenter
  parameters {

    fabric_name         = "string"
    site_name_hierarchy = "string"
  }
}

output "dnacenter_sda_fabric_site_example" {
  value = dnacenter_sda_fabric_site.example
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

Optional:

- **fabric_name** (String) Fabric Name (should be existing fabric name)
- **site_name_hierarchy** (String) Site Name Hierarchy for provision device location.


<a id="nestedatt--item"></a>
### Nested Schema for `item`

Read-Only:

- **description** (String)
- **execution_status_url** (String)
- **status** (String)

## Import

Import is supported using the following syntax:

```shell
terraform import dnacenter_sda_fabric_site.example "id:=string"
```