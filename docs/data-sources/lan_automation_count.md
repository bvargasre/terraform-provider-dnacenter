---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "dnacenter_lan_automation_count Data Source - terraform-provider-dnacenter"
subcategory: ""
description: |-
  It performs read operation on LAN Automation.
  Invoke this API to get the total count of LAN Automation sessions.
---

# dnacenter_lan_automation_count (Data Source)

It performs read operation on LAN Automation.

- Invoke this API to get the total count of LAN Automation sessions.

## Example Usage

```terraform
data "dnacenter_lan_automation_count" "example" {
  provider = dnacenter
}

output "dnacenter_lan_automation_count_example" {
  value = data.dnacenter_lan_automation_count.example.item
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- **id** (String) The ID of this resource.

### Read-Only

- **item** (List of Object) (see [below for nested schema](#nestedatt--item))

<a id="nestedatt--item"></a>
### Nested Schema for `item`

Read-Only:

- **session_count** (String)

