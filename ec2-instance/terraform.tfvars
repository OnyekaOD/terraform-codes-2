create            = true
name              = "Rpost_HA-proxy"
availability_zone = "eu-west-1a"
hibernation       = false
instance_type     = "t2.small"
key_name          = "Rpost_key"
private_ip        = true
root_block_device = [
  {
    encrypted   = false
    volume_type = "gp2"
    throughput  = 100
    volume_size = 10
    tags = {
      Name = "Rpost-root-block"
    }
  }
]
source_dest_check = true
subnet_id         = "aws_subnet.private.id"
tenancy           = "defualt"
tags = {
  "Name"        = "RPOST-HA_Proxy"
  "Environment" = "Staging"
}
enable_volume_tags          = true
ingressrules                = ["443", "22", "3306"]
egressrules                 = ["443", "22", "3306"]
associate_public_ip_address = false
volume_tags                 = "rpost-volume"
network_interface = [{
  "device_index"           = "0"
  "network_interface_id"   = null
  "delete_on_termination " = true
}]
