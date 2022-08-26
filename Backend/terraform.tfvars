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
vpc_ids_list                  = aws_vpc.rpost.id
expected_bucket_owner         = "947988792382"

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
name                           = "Terraform_Lock_Table"
hash_key                       = "LockID"
read_capacity                  = 10
write_capacity                 = 10
projection_type                = "INCLUDE"
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