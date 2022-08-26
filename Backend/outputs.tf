output "s3_bucket_id" {
  value       = aws_s3_bucket.rpost[0].id
  description = "S3 bucket ID"
}

output "s3_bucket_arn" {
  value       = aws_s3_bucket.rpost[0].arn
  description = "S3 bucket ARN"
}
output "canonical_user_id" {
  value = data.aws_canonical_user_id.current.id
}