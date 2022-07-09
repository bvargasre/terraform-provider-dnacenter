---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "dnacenter_site Resource - terraform-provider-dnacenter"
subcategory: ""
description: |-
  It manages create, read, update and delete operations on Sites.
  Creates site with area/building/floor with specified hierarchy.Update site area/building/floor with specified hierarchy and new valuesDelete site with area/building/floor by siteId.
---

# dnacenter_site (Resource)

It manages create, read, update and delete operations on Sites.

- Creates site with area/building/floor with specified hierarchy.

- Update site area/building/floor with specified hierarchy and new values

- Delete site with area/building/floor by siteId.

## Example Usage

```terraform
provider "dnacenter" {
  debug = "true"
}

resource "dnacenter_site" "example" {
  provider = dnacenter
  parameters {

    site {

      area {

        name        = "string"
        parent_name = "string"
      }
      building {

        address     = "string"
        country     = "string"
        latitude    = 1.0
        longitude   = 1.0
        name        = "string"
        parent_name = "string"
      }
      floor {

        floor_number = 1.0
        height       = 1.0
        length       = 1.0
        name         = "string"
        parent_name  = "string"
        rf_model     = "string"
        width        = 1.0
      }
    }
    site_id = "string"
    type    = "string"
  }
}

output "dnacenter_site_example" {
  value = dnacenter_site.example
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

- **type** (String) Type of site to create (eg: area, building, floor)

Optional:

- **site** (Block List, Max: 1) (see [below for nested schema](#nestedblock--parameters--site))
- **site_id** (String) siteId path parameter. Site id to which site details to be updated.

<a id="nestedblock--parameters--site"></a>
### Nested Schema for `parameters.site`

Optional:

- **area** (Block List, Max: 1) (see [below for nested schema](#nestedblock--parameters--site--area))
- **building** (Block List, Max: 1) (see [below for nested schema](#nestedblock--parameters--site--building))
- **floor** (Block List, Max: 1) (see [below for nested schema](#nestedblock--parameters--site--floor))

<a id="nestedblock--parameters--site--area"></a>
### Nested Schema for `parameters.site.area`

Optional:

- **name** (String) Name of the area (eg: Area1)
- **parent_name** (String) Parent name of the area to be created


<a id="nestedblock--parameters--site--building"></a>
### Nested Schema for `parameters.site.building`

Optional:

- **address** (String) Address of the building to be created
- **latitude** (Number) Latitude coordinate of the building (eg:37.338)
- **longitude** (Number) Longitude coordinate of the building (eg:-121.832)
- **name** (String) Name of the building (eg: building1)
- **parent_name** (String) Parent name of building to be created


<a id="nestedblock--parameters--site--floor"></a>
### Nested Schema for `parameters.site.floor`

Optional:

- **height** (Number) Height of the floor (eg: 15)
- **length** (Number) Length of the floor (eg: 100)
- **name** (String) Name of the floor (eg:floor-1)
- **parent_name** (String) Parent name of the floor to be created
- **rf_model** (String) Type of floor. Allowed values are 'Cubes And Walled Offices', 'Drywall Office Only', 'Indoor High Ceiling', 'Outdoor Open Space'.
- **width** (Number) Width of the floor (eg:100)




<a id="nestedatt--item"></a>
### Nested Schema for `item`

Read-Only:

- **additional_info** (List of Object) (see [below for nested schema](#nestedobjatt--item--additional_info))
- **id** (String)
- **instance_tenant_id** (String)
- **name** (String)
- **parent_id** (String)
- **site_hierarchy** (String)
- **site_name_hierarchy** (String)

<a id="nestedobjatt--item--additional_info"></a>
### Nested Schema for `item.additional_info`

Read-Only:

- **attributes** (List of Object) (see [below for nested schema](#nestedobjatt--item--additional_info--attributes))
- **namespace** (String)

<a id="nestedobjatt--item--additional_info--attributes"></a>
### Nested Schema for `item.additional_info.attributes`

Read-Only:

- **address** (String)
- **address_inherited_from** (String)
- **country** (String)
- **floor_index** (String)
- **height** (String)
- **latitude** (String)
- **length** (String)
- **longitude** (String)
- **offset_x** (String)
- **offset_y** (String)
- **rf_model** (String)
- **type** (String)
- **width** (String)

## Import

Import is supported using the following syntax:

```shell
terraform import dnacenter_site.example "id:=string"
```