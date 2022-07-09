---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "dnacenter_itsm_integration_events_retry Resource - terraform-provider-dnacenter"
subcategory: ""
description: |-
  It performs create operation on ITSM.
  Allows retry of multiple failed ITSM event instances. The retry request payload can be given as a list of strings:
  ["instance1","instance2","instance3",..] A minimum of one instance Id is mandatory. The list of failed event instance
  Ids can be retrieved using the 'Get Failed ITSM Events' API in the 'instanceId' attribute.
---

# dnacenter_itsm_integration_events_retry (Resource)

It performs create operation on ITSM.

- Allows retry of multiple failed ITSM event instances. The retry request payload can be given as a list of strings:
["instance1","instance2","instance3",..] A minimum of one instance Id is mandatory. The list of failed event instance
Ids can be retrieved using the 'Get Failed ITSM Events' API in the 'instanceId' attribute.

~>**Warning:**
This resource does not represent a real-world entity in Cisco DNA Center, therefore changing or deleting this resource on its own has no immediate effect.
Instead, it is a task part of a Cisco DNA Center workflow. It is executed in DNACenter without any additional verification. It does not check if it was executed before or if a similar configuration or action already existed previously.

## Example Usage

```terraform
provider "dnacenter" {
  debug = "true"
}

resource "dnacenter_itsm_integration_events_retry" "example" {
  provider   = dnacenter
  parameters = ["string"]
}

output "dnacenter_itsm_integration_events_retry_example" {
  value = dnacenter_itsm_integration_events_retry.example
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

- **payload** (List of String) Array of RequestItsmRetryIntegrationEvents


<a id="nestedatt--item"></a>
### Nested Schema for `item`

Read-Only:

- **execution_id** (String)
- **execution_status_url** (String)
- **message** (String)

