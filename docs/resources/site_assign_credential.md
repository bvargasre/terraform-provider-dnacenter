---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "dnacenter_site_assign_credential Resource - terraform-provider-dnacenter"
subcategory: ""
description: |-
  It performs create operation on Network Settings.
          - Assign Device Credential To Site
---

# dnacenter_site_assign_credential (Resource)

It performs create operation on Network Settings.
		- Assign Device Credential To Site



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

- **site_id** (String) siteId path parameter. site id to assign credential.

Optional:

- **cli_id** (String) Cli Id
- **http_read** (String) Http Read
- **http_write** (String) Http Write
- **persistbapioutput** (String) __persistbapioutput header parameter. Persist bapi sync response
- **snmp_v2_read_id** (String) Snmp V2 Read Id
- **snmp_v2_write_id** (String) Snmp V2 Write Id
- **snmp_v3_id** (String) Snmp V3 Id


<a id="nestedatt--item"></a>
### Nested Schema for `item`

Read-Only:

- **execution_id** (String)
- **execution_status_url** (String)
- **message** (String)

