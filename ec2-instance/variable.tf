variable "create" {
  description = "Whether to create an instance"
  type        = bool
}

variable "name" {
  description = "Name to be used on EC2 instance created"
  type        = string
}

variable "associate_public_ip_address" {
  description = "Whether to associate a public IP address with an instance in a VPC"
  type        = bool
}

variable "availability_zone" {
  description = "AZ to start the instance in"
  type        = string
}
variable "hibernation" {
  description = "If true, the launched EC2 instance will support hibernation"
  type        = bool
}
variable "instance_type" {
  description = "The type of instance to start"
  type        = string
}
variable "key_name" {
  description = "Key name of the Key Pair to use for the instance; which can be managed using the `aws_key_pair` resource"
  type        = string
}
variable "private_ip" {
  description = "Private IP address to associate with the instance in a VPC"
  type        = string
}

variable "root_block_device" {
  description = "Customize details about the root block device of the instance. See Block Devices below for details"
  type        = list(any)
}
variable "source_dest_check" {
  description = "Controls if traffic is routed to the instance when the destination address does not match the instance. Used for NAT or VPNs."
  type        = bool
}

variable "subnet_id" {
  description = "The VPC Subnet ID to launch in"
  type        = string
}
variable "tags" {
  description = "A mapping of tags to assign to the resource"
  type        = map(string)
}

variable "tenancy" {
  description = "The tenancy of the instance (if the instance is running in a VPC). Available values: default, dedicated, host."
  type        = string
}
variable "enable_volume_tags" {
  description = "Whether to enable volume tags (if enabled it conflicts with root_block_device tags)"
  type        = bool
}

/*variable "vpc_security_group_ids" {
  description = "A list of security group IDs to associate with"
  type        = list(string)
}*/

variable "volume_tags" {
  description = "Assigning a tag to the root volume to seperate it from thr ebs volume."
  type        = string
}
variable "ingressrules" {
  description = "Assigning a tag to the root volume to seperate it from thr ebs volume."
  type        = list(string)
}
variable "egressrules" {
  description = "Assigning a tag to the root volume to seperate it from thr ebs volume."
  type        = list(string)
}
variable "network_interface" {
  description = "Customize network interfaces to be attached at instance boot time"
  type        = list(map(string))

}
