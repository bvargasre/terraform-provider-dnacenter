---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "dnacenter_wireless_rf_profile Data Source - terraform-provider-dnacenter"
subcategory: ""
description: |-
  It performs read operation on Wireless.
  Retrieve all RF profiles
---

# dnacenter_wireless_rf_profile (Data Source)

It performs read operation on Wireless.

- Retrieve all RF profiles

## Example Usage

```terraform
data "dnacenter_wireless_rf_profile" "example" {
  provider        = dnacenter
  rf_profile_name = "string"
}

output "dnacenter_wireless_rf_profile_example" {
  value = data.dnacenter_wireless_rf_profile.example.items
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- **id** (String) The ID of this resource.
- **rf_profile_name** (String) rf-profile-name query parameter.

### Read-Only

- **items** (List of Object) (see [below for nested schema](#nestedatt--items))

<a id="nestedatt--items"></a>
### Nested Schema for `items`

Read-Only:

- **channel_width** (String)
- **default_rf_profile** (String)
- **enable_brown_field** (String)
- **enable_custom** (String)
- **enable_radio_type_a** (String)
- **enable_radio_type_b** (String)
- **name** (String)
- **radio_type_a_properties** (List of Object) (see [below for nested schema](#nestedobjatt--items--radio_type_a_properties))
- **radio_type_b_properties** (List of Object) (see [below for nested schema](#nestedobjatt--items--radio_type_b_properties))

<a id="nestedobjatt--items--radio_type_a_properties"></a>
### Nested Schema for `items.radio_type_a_properties`

Read-Only:

- **data_rates** (String)
- **mandatory_data_rates** (String)
- **max_power_level** (Number)
- **min_power_level** (Number)
- **parent_profile** (String)
- **power_threshold_v1** (Number)
- **radio_channels** (String)
- **rx_sop_threshold** (String)


<a id="nestedobjatt--items--radio_type_b_properties"></a>
### Nested Schema for `items.radio_type_b_properties`

Read-Only:

- **data_rates** (String)
- **mandatory_data_rates** (String)
- **max_power_level** (Number)
- **min_power_level** (Number)
- **parent_profile** (String)
- **power_threshold_v1** (Number)
- **radio_channels** (String)
- **rx_sop_threshold** (String)

