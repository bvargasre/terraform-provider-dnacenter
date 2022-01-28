---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "dnacenter_nfv_profile Resource - terraform-provider-dnacenter"
subcategory: ""
description: |-
  It manages create, read, update and delete operations on Site Design.
  API to create network profile for different NFV topologiesAPI to update a NFV Network profileAPI to delete nfv network profile.
---

# dnacenter_nfv_profile (Resource)

It manages create, read, update and delete operations on Site Design.

- API to create network profile for different NFV topologies

- API to update a NFV Network profile

- API to delete nfv network profile.

## Example Usage

```terraform
resource "dnacenter_nfv_profile" "example" {
  provider = dnacenter
  parameters {

    device {

      current_device_tag = "string"
      custom_networks {

        connection_type = "string"
        network_name    = "string"
        services_to_connect {

          service_name = "string"
        }
        vlan_id   = 1.0
        vlan_mode = "string"
      }
      custom_template {

        device_type   = "string"
        template      = "string"
        template_type = "string"
      }
      device_tag                          = "string"
      device_type                         = "string"
      direct_internet_access_for_firewall = "false"
      service_provider_profile {

        connect                        = "false"
        connect_default_gateway_on_wan = "false"
        link_type                      = "string"
        service_provider               = "string"
      }
      services {

        firewall_mode = "string"
        image_name    = "string"
        profile_type  = "string"
        service_name  = "string"
        service_type  = "string"
        v_nic_mapping {

          assign_ip_address_to_network = "string"
          network_type                 = "string"
        }
      }
      vlan_for_l2 {

        vlan_description = "string"
        vlan_id          = 1.0
        vlan_type        = "string"
      }
    }
    id           = "string"
    profile_name = "string"
  }
}

output "dnacenter_nfv_profile_example" {
  value = dnacenter_nfv_profile.example
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

- **id** (String) id path parameter. Id of the NFV profile to be updated
- **profile_name** (String) Name of the profile to create NFV profile

Optional:

- **device** (Block List) (see [below for nested schema](#nestedblock--parameters--device))

<a id="nestedblock--parameters--device"></a>
### Nested Schema for `parameters.device`

Optional:

- **current_device_tag** (String) Existing device tag name saved in the nfv profiles (eg: dev1)
- **custom_networks** (Block List) (see [below for nested schema](#nestedblock--parameters--device--custom_networks))
- **custom_template** (Block List) (see [below for nested schema](#nestedblock--parameters--device--custom_template))
- **device_tag** (String) Device Tag name(eg: dev1)
- **device_type** (String) Name of the device used in creating nfv profile. Allowed values are 'Cisco 5400 Enterprise Network Compute System', 'Cisco 5100 Enterprise Network Compute System'.
- **direct_internet_access_for_firewall** (String) Direct internet access value should be boolean (eg: false or true)
- **service_provider_profile** (Block List) (see [below for nested schema](#nestedblock--parameters--device--service_provider_profile))
- **services** (Block List) (see [below for nested schema](#nestedblock--parameters--device--services))
- **vlan_for_l2** (Block List) (see [below for nested schema](#nestedblock--parameters--device--vlan_for_l2))

<a id="nestedblock--parameters--device--custom_networks"></a>
### Nested Schema for `parameters.device.custom_networks`

Optional:

- **connection_type** (String) Type of network connection from custom network (eg: lan)
- **network_name** (String) Name of custom network (eg: cust-1)
- **services_to_connect** (Block List) (see [below for nested schema](#nestedblock--parameters--device--custom_networks--services_to_connect))
- **vlan_id** (Number) Vlan id for the custom network(eg: 4000)
- **vlan_mode** (String) Network mode (eg Access or Trunk)

<a id="nestedblock--parameters--device--custom_networks--services_to_connect"></a>
### Nested Schema for `parameters.device.custom_networks.vlan_mode`

Optional:

- **service_name** (String) Name of service to be connected to the custom network (eg: router-1)



<a id="nestedblock--parameters--device--custom_template"></a>
### Nested Schema for `parameters.device.custom_template`

Optional:

- **device_type** (String) Type of the device. Allowed values are 'Cisco 5400 Enterprise Network Compute System', 'Cisco Integrated Services Virtual Router', 'Cisco Adaptive Security Virtual Appliance (ASAv)', 'NFVIS', 'ASAV'.
- **template** (String) Name of the template(eg NFVIS template)
- **template_type** (String) Name of the template type to which template is associated (eg: Cloud DayN Templates). Allowed values are 'Onboarding Template(s)' and 'Day-N-Template(s)'.


<a id="nestedblock--parameters--device--service_provider_profile"></a>
### Nested Schema for `parameters.device.service_provider_profile`

Optional:

- **connect** (String) Connection of service provider and device value should be boolean (eg: true)
- **connect_default_gateway_on_wan** (String) Connect default gateway connect value as boolean (eg: true)
- **link_type** (String) Name of connection type(eg: GigabitEthernet)
- **service_provider** (String) Name of the service provider(eg: Airtel)


<a id="nestedblock--parameters--device--services"></a>
### Nested Schema for `parameters.device.services`

Optional:

- **firewall_mode** (String) Firewall mode details example (routed, transparent)
- **image_name** (String) Service image name (eg: isrv-universalk9.16.12.01a.tar.gz)
- **profile_type** (String) Profile type of service (eg: ISRv-mini)
- **service_name** (String) Name of the service (eg: Router-1)
- **service_type** (String) Service type (eg: ISRV)
- **v_nic_mapping** (Block List) (see [below for nested schema](#nestedblock--parameters--device--services--v_nic_mapping))

<a id="nestedblock--parameters--device--services--v_nic_mapping"></a>
### Nested Schema for `parameters.device.services.v_nic_mapping`

Optional:

- **assign_ip_address_to_network** (String) Assign ip address to network (eg: true or false)
- **network_type** (String) Type of connection (eg:  wan, lan or internal)



<a id="nestedblock--parameters--device--vlan_for_l2"></a>
### Nested Schema for `parameters.device.vlan_for_l2`

Optional:

- **vlan_description** (String) Vlan description(eg: Access 4018)
- **vlan_id** (Number) Vlan id (eg: 4018)
- **vlan_type** (String) Vlan type(eg: Access or Trunk)




<a id="nestedatt--item"></a>
### Nested Schema for `item`

Read-Only:

- **device** (List of Object) (see [below for nested schema](#nestedobjatt--item--device))
- **id** (String)
- **profile_name** (String)

<a id="nestedobjatt--item--device"></a>
### Nested Schema for `item.device`

Read-Only:

- **custom_networks** (List of Object) (see [below for nested schema](#nestedobjatt--item--device--custom_networks))
- **custom_template** (List of Object) (see [below for nested schema](#nestedobjatt--item--device--custom_template))
- **device_tag** (String)
- **device_type** (String)
- **direct_internet_access_for_firewall** (String)
- **service_provider_profile** (List of Object) (see [below for nested schema](#nestedobjatt--item--device--service_provider_profile))
- **services** (List of Object) (see [below for nested schema](#nestedobjatt--item--device--services))
- **vlan_for_l2** (List of Object) (see [below for nested schema](#nestedobjatt--item--device--vlan_for_l2))

<a id="nestedobjatt--item--device--custom_networks"></a>
### Nested Schema for `item.device.custom_networks`

Read-Only:

- **connection_type** (String)
- **network_name** (String)
- **services_to_connect** (List of Object) (see [below for nested schema](#nestedobjatt--item--device--custom_networks--services_to_connect))
- **vlan_id** (String)
- **vlan_mode** (String)

<a id="nestedobjatt--item--device--custom_networks--services_to_connect"></a>
### Nested Schema for `item.device.custom_networks.vlan_mode`

Read-Only:

- **service_name** (String)



<a id="nestedobjatt--item--device--custom_template"></a>
### Nested Schema for `item.device.custom_template`

Read-Only:

- **device_type** (String)
- **template** (String)
- **template_type** (String)


<a id="nestedobjatt--item--device--service_provider_profile"></a>
### Nested Schema for `item.device.service_provider_profile`

Read-Only:

- **connect** (String)
- **connect_default_gateway_on_wan** (String)
- **link_type** (String)
- **service_provider** (String)


<a id="nestedobjatt--item--device--services"></a>
### Nested Schema for `item.device.services`

Read-Only:

- **firewall_mode** (String)
- **image_name** (String)
- **profile_type** (String)
- **service_name** (String)
- **service_type** (String)
- **v_nic_mapping** (List of Object) (see [below for nested schema](#nestedobjatt--item--device--services--v_nic_mapping))

<a id="nestedobjatt--item--device--services--v_nic_mapping"></a>
### Nested Schema for `item.device.services.v_nic_mapping`

Read-Only:

- **assign_ip_address_to_network** (String)
- **network_type** (String)



<a id="nestedobjatt--item--device--vlan_for_l2"></a>
### Nested Schema for `item.device.vlan_for_l2`

Read-Only:

- **vlan_description** (String)
- **vlan_id** (String)
- **vlan_type** (String)

## Import

Import is supported using the following syntax:

```shell
terraform import dnacenter_nfv_profile.example "id:=string"
```