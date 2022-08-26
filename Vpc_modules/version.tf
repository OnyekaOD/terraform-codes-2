terraform {
  required_version = ">= 0.13"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 3.63"
    }
  }
}
provider "aws" {
  region  = "eu-west-1"
  profile = "default"
}