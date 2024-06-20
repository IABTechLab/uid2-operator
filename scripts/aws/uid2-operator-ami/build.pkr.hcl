build {
  sources = ["source.amazon-ebs.linux"]

  provisioner "shell" {
    inline = [
      "sudo yum -y install python-pip",
      "python3 -m pip install --user ansible-core==2.11.10"]
  }

  provisioner "file" {
    source      = "./artifacts"
    destination = "/tmp"
  }

  provisioner "ansible" {
    playbook_file = "./ansible/playbook.yml"
    extra_arguments = [ "--scp-extra-args", "'-O'" ]
    skip_version_check = false
  }

  post-processor "manifest" {
    output = "manifest.json"
    strip_path = true
  }
}

