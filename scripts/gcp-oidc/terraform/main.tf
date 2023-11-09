provider "google" {
  project = var.project_id
  region  = var.region
}

module "project_services" {
  source  = "terraform-google-modules/project-factory/google//modules/project_services"
  version = "~>14.3.0"

  project_id = var.project_id

  activate_apis = [
    "compute.googleapis.com",
    "confidentialcomputing.googleapis.com",
    "logging.googleapis.com",
    "secretmanager.googleapis.com"
  ]

  disable_services_on_destroy = false
}

module "service_account" {
  depends_on  = [module.project_services]
  source      = "terraform-google-modules/service-accounts/google"
  version     = "~>4.2.1"
  project_id  = var.project_id
  names       = [var.service_account_name]
  description = "Service account to bring up confidential VMs"
  project_roles = [
    "${var.project_id}=>roles/confidentialcomputing.workloadUser",
    "${var.project_id}=>roles/logging.logWriter",
    "${var.project_id}=>roles/secretmanager.secretAccessor",
  ]
}

resource "google_compute_network" "default" {
  depends_on              = [module.project_services]
  name                    = var.network_name
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "default" {
  depends_on               = [module.project_services]
  name                     = var.network_name
  ip_cidr_range            = "10.127.0.0/20"
  network                  = google_compute_network.default.self_link
  region                   = var.region
  private_ip_google_access = true
}

resource "google_compute_router" "default" {
  depends_on = [module.project_services]
  name       = "lb-http-router"
  network    = google_compute_network.default.self_link
  region     = var.region
}

module "cloud_nat" {
  depends_on = [module.project_services]
  source     = "terraform-google-modules/cloud-nat/google"
  version    = "4.1.0"
  router     = google_compute_router.default.name
  project_id = var.project_id
  region     = var.region
  name       = "cloud-nat-lb-http-router"
}

data "google_compute_image" "confidential_space_image" {
  depends_on = [module.project_services]
  family     = var.debug_mode ? "confidential-space-debug" : "confidential-space"
  project    = "confidential-space-images"
}

data "google_secret_manager_secret_version" "uid_operater_key" {
  depends_on = [module.project_services]
  count      = var.uid_operator_key == "" ? 1 : 0
  secret     = var.uid_operator_key_secret_name
}

module "secret-manager" {
  depends_on = [module.project_services]
  source     = "GoogleCloudPlatform/secret-manager/google"
  version    = "~> 0.1"
  project_id = var.project_id
  secrets = [
    {
      name                  = var.uid_operator_key_secret_name
      secret_data           = var.uid_operator_key != "" ? var.uid_operator_key : data.google_secret_manager_secret_version.uid_operater_key[0].secret_data
      automatic_replication = true
    },
  ]
}

resource "google_compute_instance_template" "uid_operator" {
  depends_on   = [module.project_services]
  name_prefix  = "uid-operator-cs-template-"
  machine_type = var.uid_deployment_env == "prod" ? "n2d-standard-16" : "n2d-standard-2"

  tags = [var.network_name]

  disk {
    source_image = data.google_compute_image.confidential_space_image.self_link
  }

  metadata = {
    tee-image-reference            = var.uid_operator_image
    tee-container-log-redirect     = var.debug_mode
    tee-restart-policy             = "Never"
    tee-env-DEPLOYMENT_ENVIRONMENT = var.uid_deployment_env
    tee-env-API_TOKEN_SECRET_NAME  = module.secret-manager.secret_versions[0]
  }

  network_interface {
    network    = google_compute_network.default.name
    subnetwork = google_compute_subnetwork.default.name
  }

  confidential_instance_config {
    enable_confidential_compute = true
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_integrity_monitoring = true
    enable_vtpm                 = true
  }

  service_account {
    email  = module.service_account.email
    scopes = ["cloud-platform"]
  }

  scheduling {
    on_host_maintenance = "TERMINATE"
  }

  lifecycle {
    create_before_destroy = true
  }
}

module "mig" {
  depends_on          = [module.project_services]
  source              = "terraform-google-modules/vm/google//modules/mig"
  version             = "~>9.0.0"
  instance_template   = google_compute_instance_template.uid_operator.self_link
  region              = var.region
  project_id          = var.project_id
  hostname            = var.network_name
  autoscaling_enabled = true
  min_replicas        = var.min_replicas
  max_replicas        = var.max_replicas
  autoscaling_cpu = [{
    target            = 0.75
    predictive_method = "OPTIMIZE_AVAILABILITY"
  }]
  named_ports = [{
    name = "http",
    port = 8080
  }]
  update_policy = [{
    type                           = "PROACTIVE"
    instance_redistribution_type   = "PROACTIVE"
    minimal_action                 = "REPLACE"
    most_disruptive_allowed_action = "REPLACE"
    replacement_method             = "SUBSTITUTE"
    max_surge_fixed                = 3
    max_surge_percent              = null
    max_unavailable_fixed          = 0
    max_unavailable_percent        = null
    min_ready_sec                  = 60
  }]
}

module "gce_lb_http" {
  depends_on                      = [module.project_services]
  source                          = "GoogleCloudPlatform/lb-http/google"
  version                         = "~>9.2.0"
  name                            = "mig-http-lb"
  project                         = var.project_id
  target_tags                     = [var.network_name]
  firewall_networks               = [google_compute_network.default.name]
  ssl                             = var.ssl
  https_redirect                  = var.ssl
  managed_ssl_certificate_domains = var.ssl_certificate_domains

  backends = {
    default = {
      protocol    = "HTTP"
      port        = 8080
      port_name   = "http"
      timeout_sec = 10
      enable_cdn  = false

      health_check = {
        request_path = "/ops/healthcheck"
        port         = 8080
      }

      log_config = {
        enable = false
      }

      groups = [
        {
          group = module.mig.instance_group
        }
      ]

      iap_config = {
        enable = false
      }
    }
  }
}
