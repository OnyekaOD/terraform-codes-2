create = true
vpc_id = "module.vpc.vpc_id.id"
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
subnet_ids = ["aws_subnet.public.id"]
tags = {
  "Name" = "vpc-endpoints"
}
timeouts = {
  "creating" = "5"
  "deleting" = "5"
}