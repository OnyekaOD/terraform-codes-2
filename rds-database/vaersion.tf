terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.6"
    }

    random = {
      source  = "hashicorp/random"
      version = ">= 3.1"
    }
  }
}
provider "aws" {
  region = "eu-west-1"
}