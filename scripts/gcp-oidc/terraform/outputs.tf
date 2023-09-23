output "load_balancer_ip" {
  value = module.gce_lb_http.external_ip
}
