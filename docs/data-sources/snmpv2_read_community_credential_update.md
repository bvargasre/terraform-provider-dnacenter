---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "dnacenter_snmpv2_read_community_credential_update Data Source - terraform-provider-dnacenter"
subcategory: ""
description: |-
  It performs update operation on Discovery.
  Updates global SNMP read community
---

# dnacenter_snmpv2_read_community_credential_update (Data Source)

It performs update operation on Discovery.

- Updates global SNMP read community

## Example Usage

```terraform
data "dnacenter_snmpv2_read_community_credential_update" "example" {
  provider        = dnacenter
  comments        = "string"
  credential_type = "string"
  description     = "string"
  instance_uuid   = "string"
  read_community  = "string"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- **comments** (String) Comments to identify the credential
- **credential_type** (String) Credential type to identify the application that uses the credential
- **description** (String) Name/Description of the credential
- **id** (String) The ID of this resource.
- **instance_uuid** (String)
- **read_community** (String) SNMP read community. NO!$DATA!$ for no value change

### Read-Only

- **item** (List of Object) (see [below for nested schema](#nestedatt--item))

<a id="nestedatt--item"></a>
### Nested Schema for `item`

Read-Only:

- **task_id** (String)
- **url** (String)

