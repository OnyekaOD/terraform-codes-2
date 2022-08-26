provider "aws" {
  region = "eu-west-1"
}
module "Vpc_modules" {
  source              = ".//Vpc_modules"
  cidr                = "10.0.0.0/20"
  enable_ipv6         = false
  enable_dhcp_options = false
  dhcp_options_tags = {
    "Name" = "RDG_RPOST-dhcp"
  }
  enable_dns_hostnames           = true
  enable_dns_support             = true
  enable_classiclink             = true
  enable_classiclink_dns_support = true
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
  public_subnets          = ["10.0.10.0/24", "10.0.11.0/24"]
  map_public_ip_on_launch = true
  private_subnets         = ["10.0.40.0/24", "10.0.41.0/24"]
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
  reuse_nat_ips          = true
  external_nat_ips       = ["10.0.0.10", "10.0.0.11"]
  external_nat_ip_ids    = ["nbyueguuii223", "yg78egfyef235"]
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

}
module "vpc-endpoints" {
  source = ".//Vpc_modules/vpc-endpoints"
  create = true
  vpc_id = "module.Vpc_module.vpc_id"
  endpoints = {
    s3 = {
      service = "s3"
      tags    = { Name = "s3-vpc-endpoint" }
    },
    dynamodb = {
      service         = "dynamodb"
      service_type    = "Gateway"
      route_table_ids = "flatten([ infrastuctue.Vpc_modules.private_route_table_ids, module.Vpc_modules.public_route_table_ids])"
      policy          = "data.aws_iam_policy_document.dynamodb_endpoint_policy.json"
      tags            = { Name = "dynamodb-vpc-endpoint" }
    },
  }
  security_group_ids = ["data.aws_security_group.default.id"]
  subnet_ids         = ["infrastructure.Vpc_modules.private_subnets.ids"]
  tags = {
    "Name" = "vpc-endpoints"
  }
  timeouts = {
    "creating" = "5"
    "deleting" = "5"
  }
}
module "Backend" {
  source                                = ".//Backend"
  create_bucket                         = true
  attach_deny_insecure_transport_policy = true
  attach_require_latest_tls_policy      = true
  attach_policy                         = true
  attach_public_policy                  = false
  versioning = {
    status     = true
    mfa_delete = false
  }
  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        kms_rpost_key_id = "aws_kms_key.rpostkey.arn"
        sse_algorithm    = "aws:kms"
      }
    }
  }
  lifecycle_rule = {
    prevent_destroy = "enable"
  }
  bucket_prefix = "RDG"
  acl           = "private"
  #read_capacity = 5
  #write_capacity = 5
  force_destroy                 = false
  enable_server_side_encryption = true
  block_public_acls             = true
  ignore_public_acls            = true
  block_public_policy           = true
  restrict_public_buckets       = true
  enforce_vpc_requests          = true
  #vpc_ids_list = module.Vpc_modules.vpc_id
  expected_bucket_owner = "947988792382"

  logging = {
    target_bucket = "aws_s3_bucket.rpost[0].id"
    target_prefix = "log/"
  }
  tags = {
    "Name" = "rdg_rpost_backend"
  }
  grant = {
    id          = "data.aws_canonical_user_id.current_user.id"
    type        = "CanonicalUser"
    permissions = ["FULL_CONTROL"]
  }
  bucket = "RPOST_backend_tfstate"
  owner = {
    "Name" = "aws_vpc.rpost.id"
  }
  name           = "Terraform_Lock_Table"
  hash_key       = "LockID"
  read_capacity  = 10
  write_capacity = 10
  #projection_type    = "INCLUDE"
  table_class                    = "STANDARD"
  ttl_enabled                    = false
  range_key                      = "terraform-tfstate"
  point_in_time_recovery_enabled = false
  attributes = [{
    "name" = "LockID"
    "type" = "S"
    },
    {
      "name" = "terraform-tfstate",
      "type" = "S"
  }]
  #server_side_encryption_enabled = false
  #server_side_encryption_kms_key_arn = "aws_kms_key.rpostkey.arn"
  create_table = true
  global_secondary_indexes = [
    {
      name            = "Terraform_Lock_Table"
      hash_key        = "LockID"
      range_key       = "terraform-tfstate"
      projection_type = "INCLUDE"
      write_capacity  = 10
      read_capacity   = 10
    }
  ]
  local_secondary_indexes = [
    {
      name            = "Terraform_Lock_Table"
      hash_key        = "LockID"
      range_key       = "terraform-tfstate"
      projection_type = "INCLUDE"
    }
  ]
}
module "ec2" {
  source            = ".//ec2-instance"
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
}
module "rds" {
  source                         = ".//rds-database"
  identifier                     = "rdg-stage-mysql-db"
  instance_use_identifier_prefix = true
  db_name                        = "rpost-stage-db"
  engine                         = "mysql"
  engine_version                 = "8.0.28"
  family                         = "mysql-8-0" # DB parameter group
  major_engine_version           = "8.0"       # DB option group
  instance_class                 = "db.m6g.large"
  allocated_storage              = 100
  max_allocated_storage          = 300
  storage_type                   = "io1"
  db_instance_tags = {
    "name"      = "rpost_instance",
    "Sensitive" = "high"
  }
  db_parameter_group_tags = {
    "name"      = "rpost_parameter",
    "Sensitive" = "high"
  }
  # Encryption at rest is not available for DB instances running SQL Server Express Edition
  storage_encrypted                   = true
  snapshot_identifier                 = "rdg-stage-mysql-db-snapshot"
  iam_database_authentication_enabled = true
  username                            = "admin"
  port                                = 3306
  iops                                = 1000
  random_password_length              = 10
  create_random_password              = true
  deletion_protection                 = true
  #domain               = aws_directory_service_directory.demo.id
  #domain_iam_role_name = aws_iam_role.rds_ad_auth.name
  performance_insights_kms_key_id = "rghsymgdfhgvcxsdge"
  multi_az                        = true
  #subnet_ids                             = module.Vpc_module.public_subnets
  vpc_security_group_ids                 = ["aws_security_group.allow_tls.id"]
  availability_zone                      = "eu-west-1a"
  maintenance_window                     = "sun:02:00-sun:02:30"
  backup_window                          = "00:00-00:30"
  enabled_cloudwatch_logs_exports        = ["error", "audit", "general"]
  create_cloudwatch_log_group            = true
  auto_minor_version_upgrade             = true
  backup_retention_period                = 7
  skip_final_snapshot                    = true
  apply_immediately                      = false
  performance_insights_enabled           = true
  performance_insights_retention_period  = 7
  create_monitoring_role                 = true
  monitoring_interval                    = 60
  monitoring_role_name                   = "rds-monitoring-role"
  allow_major_version_upgrade            = false
  create_db_parameter_group              = true
  license_model                          = "license-included"
  timezone                               = "GMT Standard Time"
  character_set_name                     = "Latin1_General_CI_AS"
  create_db_instance                     = true
  create_db_subnet_group                 = false
  cloudwatch_log_group_kms_key_id        = "fur5yu4ye4yr5u5u54yyr5"
  cloudwatch_log_group_retention_in_days = 7
  #monitoring_role_arn                    = data.aws_iam_role.monitoring_role.arn
  publicly_accessible = true
  kms_key_id          = "rwer3werhgfjh54y4"
  tags = {
    "name" = "rpost"
  }
  parameter_group_description     = "for enabling parameters"
  parameter_group_name            = "db_parameters"
  parameter_group_use_name_prefix = false
}
module "nlb" {
  source                           = ".//network-lb"
  vpc_id                           = "module.Vpc_modules.id"
  subnet_ids                       = ["module.Vpc_modules.public_subnet_id"]
  deployment_identifier            = "staging"
  enable_cross_zone_load_balancing = "no"
  include_public_dns_record        = "no"
  include_private_dns_record       = "yes"
  expose_to_public_internet        = "yes"
  use_https                        = "yes"
  target_group_port                = 443
  target_group_type                = "instance"
  target_group_protocol            = "TCP"
  health_check_port                = "443"
  health_check_protocol            = "TCP"
  health_check_interval            = 30
  health_check_unhealthy_threshold = 3
  health_check_healthy_threshold   = 3
  listener_port                    = 443
  listener_protocol                = "TLS"
  component                        = "network"
  region                           = "eu-west-1"
}