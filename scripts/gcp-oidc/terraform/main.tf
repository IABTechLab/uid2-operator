provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

resource "google_compute_network" "default" {
  name                    = "uid-operator-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "default" {
  name                     = "uid-operator-vpc-sub"
  ip_cidr_range            = "10.127.0.0/20"
  network                  = google_compute_network.default.self_link
  region                   = var.region
  private_ip_google_access = true
}

resource "google_compute_router" "default" {
  name    = "lb-http-router"
  network = google_compute_network.default.self_link
  region  = var.region
}

module "cloud-nat" {
  source     = "terraform-google-modules/cloud-nat/google"
  version    = "~> 2.2"
  router     = google_compute_router.default.name
  project_id = var.project_id
  region     = var.region
  name       = "cloud-nat-lb-http-router"
}

data "google_compute_image" "confidential_space_image" {
  family  = "confidential-space-debug"
  project = "confidential-space-images"
}


resource "google_compute_instance_template" "uid_operator" {
  name         = "confidential-instance-tf"
  machine_type = var.uid_machine_type

  tags = ["confidential"]

  disk {
    source_image = data.google_compute_image.confidential_space_image.self_link
  }

  metadata = {
    tee-image-reference = var.uid_operator_image
    tee-container-log-redirect = true
    tee-restart-policy = "Never"
    tee-env-DEPLOYMENT_ENVIRONMENT = var.uid_deployment_env
    tee-env-API_TOKEN = var.uid_api_token
  }

  network_interface {
    network = google_compute_network.default.name
    subnetwork = google_compute_subnetwork.default.name
  }

  confidential_instance_config {
    enable_confidential_compute = true
  }

  shielded_instance_config {
    enable_secure_boot = true
    enable_integrity_monitoring = true
    enable_vtpm = true
  }

  service_account {
    email = "gcp-oidc-test@uid2-test.iam.gserviceaccount.com"
    scopes = ["cloud-platform"]
  } 

  scheduling {
    on_host_maintenance = "TERMINATE"
  }
}

module "mig" {
  source            = "terraform-google-modules/vm/google//modules/mig"
  version           = "9.0.0"
  instance_template = google_compute_instance_template.uid_operator.self_link
  region            = var.region
  project_id        = var.project_id
  hostname          = "uid-operator"
  target_size       = 2
  named_ports = [{
    name = "http",
    port = 8080
  }]
}

module "gce-lb-http" {
  source            = "GoogleCloudPlatform/lb-http/google"
  version           = "9.2.0"
  name              = "mig-http-lb"
  project           = var.project_id
  target_tags       = ["confidential"]
  firewall_networks = [google_compute_network.default.name]


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