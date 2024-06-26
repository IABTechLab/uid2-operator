build {
  sources = ["source.amazon-ebs.linux"]

  provisioner "file" {
    source      = "./artifacts"
    destination = "/tmp"
  }

  provisioner "ansible" {
    playbook_file = "./ansible/playbook.yml"
    extra_arguments = [ "--scp-extra-args", "'-O'" ]
  }

  post-processor "manifest" {
    output = "manifest.json"
    strip_path = true
  }
}

