terraform {
  required_providers {
    dnacenter = {
      version = "1.1.18-beta"
      source  = "hashicorp.com/edu/dnacenter"
      # "hashicorp.com/edu/dnacenter" is the local built source, change to "cisco-en-programmability/dnacenter" to use downloaded version from registry
    }
  }
}

provider "dnacenter" {
}

data "dnacenter_snmp_properties" "example" {
  provider = dnacenter
}

output "dnacenter_snmp_properties_example" {
  value = data.dnacenter_snmp_properties.example.items
}
