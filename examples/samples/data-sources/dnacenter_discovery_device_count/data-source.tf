terraform {
  required_providers {
    dnacenter = {
      version = "1.0.9-beta"
      source  = "hashicorp.com/edu/dnacenter"
      # "hashicorp.com/edu/dnacenter" is the local built source, change to "cisco-en-programmability/dnacenter" to use downloaded version from registry
    }
  }
}

provider "dnacenter" {
}

data "dnacenter_discovery_device_count" "example" {
  provider = dnacenter
  id       = 1
}

output "dnacenter_discovery_device_count_example" {
  value = data.dnacenter_discovery_device_count.example.item
}
