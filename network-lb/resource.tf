resource "aws_lb" "rpost-nlb" {
  load_balancer_type = "network"

  name    = "nlb-${var.component}"
  subnets = var.subnet_ids

  internal = var.expose_to_public_internet == "yes" ? false : true

  enable_cross_zone_load_balancing = var.enable_cross_zone_load_balancing == "yes" ? true : false

  #idle_timeout = var.idle_timeout

  tags = {
    Name                 = "nlb-${var.component}-${var.deployment_identifier}"
    Component            = var.component
    DeploymentIdentifier = var.deployment_identifier
  }
}
###############################################################################
resource "aws_cloudwatch_log_metric_filter" "nlb" {
  name           = "network-loadbalancer"
  pattern        = ""
  log_group_name = aws_cloudwatch_log_group.nlb.name

  metric_transformation {
    name      = "unhealthy"
    namespace = "nlb-healthcheck"
    value     = "3"
  }
}

resource "aws_cloudwatch_log_group" "nlb" {
  name = "Rpost-nlb"
}



resource "aws_cloudwatch_metric_alarm" "rpost" {
  alarm_name          = "alb-alarams"
  alarm_description   = "unhealthy"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 3
  threshold           = 3
  period              = 60
  unit                = "Count"
  namespace           = "nlb-healthcheck"
  metric_name         = "UnHealthyHostCount"
  statistic           = "Sum"
  alarm_actions       = ["arn:aws:sns:eu-west-1:124531745575:nlb-alerts"]

  dimensions = {
    #TargetGroup = aws_lb_target_group.lb-tg.arn_suffix
    LoadBalancer = aws_lb.rpost-nlb.arn_suffix
  }
}