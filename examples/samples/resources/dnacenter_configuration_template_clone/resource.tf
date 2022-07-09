terraform {
  required_providers {
    dnacenter = {
      version = "1.0.1-beta"
      source  = "hashicorp.com/edu/dnacenter"
      # "hashicorp.com/edu/dnacenter" is the local built source, change to "cisco-en-programmability/dnacenter" to use downloaded version from registry
    }
  }
}

resource "dnacenter_configuration_template_clone" "example" {
  provider = dnacenter
 
  parameters {
    name        = "string"
    project_id  = "string"
    template_id = "string"
  }
}