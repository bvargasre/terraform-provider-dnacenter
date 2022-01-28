---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "dnacenter_event_subscription_details_email Data Source - terraform-provider-dnacenter"
subcategory: ""
description: |-
  It performs read operation on Event Management.
  Gets the list of subscription details for specified connectorType
---

# dnacenter_event_subscription_details_email (Data Source)

It performs read operation on Event Management.

- Gets the list of subscription details for specified connectorType

## Example Usage

```terraform
data "dnacenter_event_subscription_details_email" "example" {
  provider       = dnacenter
  connector_type = "string"
  instance_id    = "string"
  name           = "string"
}

output "dnacenter_event_subscription_details_email_example" {
  value = data.dnacenter_event_subscription_details_email.example.items
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- **connector_type** (String) connectorType query parameter. Connector Type [EMAIL]

### Optional

- **id** (String) The ID of this resource.
- **instance_id** (String) instanceId query parameter. Instance Id of the specific configuration
- **name** (String) name query parameter. Name of the specific configuration

### Read-Only

- **items** (List of Object) (see [below for nested schema](#nestedatt--items))

<a id="nestedatt--items"></a>
### Nested Schema for `items`

Read-Only:

- **connector_type** (String)
- **description** (String)
- **from_email_address** (String)
- **instance_id** (String)
- **name** (String)
- **subject** (String)
- **to_email_addresses** (List of String)

