---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "dnacenter_site_count Data Source - terraform-provider-dnacenter"
subcategory: ""
description: |-
  It performs read operation on Sites.
  API to get site count
---

# dnacenter_site_count (Data Source)

It performs read operation on Sites.

- API to get site count

## Example Usage

```terraform
data "dnacenter_site_count" "example" {
  provider = dnacenter
  site_id  = "string"
}

output "dnacenter_site_count_example" {
  value = data.dnacenter_site_count.example.item
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- **id** (String) The ID of this resource.
- **site_id** (String) siteId query parameter. Site id to retrieve site count.

### Read-Only

- **item** (List of Object) (see [below for nested schema](#nestedatt--item))

<a id="nestedatt--item"></a>
### Nested Schema for `item`

Read-Only:

- **response** (Number)
- **version** (String)

