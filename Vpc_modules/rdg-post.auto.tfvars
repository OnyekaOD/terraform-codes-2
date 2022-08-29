
cidr                = "10.0.0.0/20"
enable_ipv6         = false
enable_dhcp_options = false
dhcp_options_tags = {
  "Name" = "RDG_RPOST-dhcp"
}
enable_dns_hostnames           = true
enable_dns_support             = true
enable_classiclink             = false
enable_classiclink_dns_support = false
tags = {
  "Environment" = "staging",
  "Name"        = "rdg_rpost"
}
vpc_tags = {
  "Name"        = "RDG_RPOST_VPC",
  "Environment" = "staging"
}

name       = "rpost"
create_igw = true
igw_tags = {
  "Owner"       = "rdg_rpost",
  "Environment" = "staging",
  "Name"        = "rdg_rpost_internet_gateway"
}
manage_default_security_group = true
default_security_group_name   = "RDG_RPOST-security_group"
default_security_group_ingress = [
  {
    from_port = 22
    to_port   = 22
    protocol  = "TCP"
  },
  {
    from_port = 443
    to_port   = 443
    protocol  = "TCP"
  },
  {
    from_port = 3306
    to_port   = 3306
    protocol  = "TCP"
  },
]
default_security_group_egress = [{
  from_port = 0
  to_port   = 0
  protocol  = -1
}]
default_security_group_tags = {
  "Name" = "RDG_RPOST-security_group"
}
manage_default_route_table = true
default_route_table_routes = [{
  "default_route_table_id" = "aws_vpc.rpost.default_route_table.id"
  "cidr_block"             = "10.0.0.0/20"
}]

default_route_table_tags = {
  "Name" = "RDG_RPOST-route_table"
}
public_subnet_suffix = "public"
public_route_table_tags = {
  "Name" = "RDG_RPOST_public_route_table"
}
private_subnet_suffix = "private"
public_subnet_tags = {
  "Name" = "RDG_RPOST"
}
private_subnet_tags = {
  "Name" = "RDG_RPOST"
}
azs = ["eu-west-1a", "eu-west-1b"]
private_route_table_tags = {
  "Name" = "RDG_RPOST_private_route_table"
}
public_subnets          = ["10.0.1.0/24", "10.0.3.0/24"]
map_public_ip_on_launch = true
private_subnets         = ["10.0.4.0/24", "10.0.5.0/24"]
public_acl_tags = {
  "Name" = "RDG_RPOST-pub_acl"
}
public_outbound_acl_rules = [{
  "rule_number" = "99"
  "rule_action" = "deny"
  "from_port"   = "0"
  "to_port"     = "0"
  "protocol"    = "-1"
  "cidr_block"  = "0.0.0.0/0"
}]
public_inbound_acl_rules = [{
  "rule_number" = "95"
  "rule_action" = "allow"
  "from_port"   = "443"
  "to_port"     = "443"
  "protocol"    = "-1"
  "cidr_block"  = "0.0.0.0/0"
  },
  {
    "rule_number" = "98"
    "rule_action" = "allow"
    "from_port"   = "22"
    "to_port"     = "22"
    "protocol"    = "-1"
    "cidr_block"  = "0.0.0.0/0"
  },
  {
    "rule_number" = "97"
    "rule_action" = "allow"
    "from_port"   = "3306"
    "to_port"     = "3306"
    "protocol"    = "-1"
    "cidr_block"  = "0.0.0.0/0"
  }
]
public_dedicated_network_acl  = true
private_dedicated_network_acl = true

private_inbound_acl_rules = [{
  rule_number = 80
  rule_action = "allow"
  from_port   = 22
  to_port     = 22
  protocol    = "-1"
  cidr_block  = "10.0.0.0/24"
  },
  {
    rule_number = 85
    rule_action = "allow"
    from_port   = 443
    to_port     = 443
    protocol    = "-1"
    cidr_block  = "10.0.0.0/24"
  }
]
private_outbound_acl_rules = [{
  rule_number = 92
  rule_action = "allow"
  from_port   = 443
  to_port     = 443
  protocol    = "-1"
  cidr_block  = "0.0.0.0/0"
  },
  {
    rule_number = 90
    rule_action = "deny"
    from_port   = "0"
    to_port     = "0"
    protocol    = "-1"
    cidr_block  = "0.0.0.0/0"
  }
]
#allocation_id = ["aws_eip.eip[*].id"]
reuse_nat_ips          = false
external_nat_ips       = ["10.0.1.20", "10.0.3.21"]
external_nat_ip_ids    = ["(aws_eip.nat[0].id)", "(aws_eip.nat[1].id)" ]
enable_nat_gateway     = true
single_nat_gateway     = false
one_nat_gateway_per_az = true
nat_eip_tags = {
  "Name" = "RDG_RPOST-eip"
}
nat_gateway_tags = {
  "Name" = "RDG_RPOST-nat_gateway"
}
vpc_flow_log_tags = {
  "Name" = "RDG_RPOST-vpc_flow_logs"
}
enable_flow_log                      = true
create_flow_log_cloudwatch_log_group = true
create_flow_log_cloudwatch_iam_role  = true
flow_log_traffic_type                = "ALL"
flow_log_destination_type            = "cloud-watch-logs"
flow_log_destination_arn             = "aws_cloudwatch_log_group.flow_log.arn"
flow_log_cloudwatch_iam_role_arn     = "aws_iam_role.vpc_flow_log_cloudwatch.arn"

flow_log_cloudwatch_log_group_retention_in_days = 7
flow_log_cloudwatch_log_group_name_prefix       = "/aws/vpc-flow-log/"
flow_log_max_aggregation_interval               = 60

default_network_acl_ingress = [{
  rule_no    = 100
  action     = "allow"
  from_port  = 0
  to_port    = 0
  protocol   = "-1"
  cidr_block = "0.0.0.0/0"
  },
  {
    rule_no         = 101
    action          = "allow"
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    ipv6_cidr_block = "::/0"
}]
default_network_acl_egress = [{
  rule_no    = 100
  action     = "allow"
  from_port  = 0
  to_port    = 0
  protocol   = "-1"
  cidr_block = "0.0.0.0/0"
  },
  {
    rule_no         = 101
    action          = "allow"
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    ipv6_cidr_block = "::/0"
}]
