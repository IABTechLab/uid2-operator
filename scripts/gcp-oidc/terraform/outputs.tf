output "load-balancer-ip" {
  value = module.gce_lb_http.external_ip
}
