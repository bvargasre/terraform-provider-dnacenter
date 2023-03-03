
terraform {
  required_providers {
    dnacenter = {
      version = "1.0.19-beta"
      source  = "hashicorp.com/edu/dnacenter"
      # "hashicorp.com/edu/dnacenter" is the local built source change to "cisco-en-programmability/dnacenter" to use downloaded version from registry
    }
  }
}

provider "dnacenter" {
  debug = "true"
}

resource "dnacenter_configuration_template_export_project" "example" {
  provider = dnacenter

  parameters {
    payload = ["string"]
  }
}