#!/bin/bash

sudo yum install -y aws-amitools-ec2
sudo yum upgrade -y aws-amitools-ec2

# disable password-based remote logins for root
sudo sed -i '/#PermitRootLogin/c\PermitRootLogin without-password' /etc/ssh/sshd_config

# remove SSH host key pairs
$(sudo shred -u /etc/ssh/*_key /etc/ssh/*_key.pub 2>/dev/null) || echo 'no ssh host key pairs to remove'

# remove SSH authorized_keys
$(shred -u ~/.ssh/authorized_keys 2>/dev/null) || echo 'no ssh authorized_keys to remove'

# install public key creds
# add init script to fetch public key at start time and load ssh keys
# nothing to do: cloud-init has already done this for us

# delete bash history
$(shred -u ~/.*history 2>/dev/null) || echo 'no bash history to remove'
