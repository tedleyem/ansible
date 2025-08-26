Vagrant.configure("2") do |config|
#required_version ">= 1.8.0"
# Defining the VM
  vms = [
    { name: "debian12", box: "generic/debian12", ip: "192.168.56.10" },
    { name: "ubuntu2204", box: "generic/ubuntu2204", ip: "192.168.56.11" },
    { name: "ubuntu2404", box: "generic/ubuntu2404", ip: "192.168.56.12" },
    { name: "rhel8", box: "generic/rhel8", ip: "192.168.56.14" },
    { name: "rhel9", box: "genereal/rhel9", ip: "192.168.56.15" }
  ]
  # Configure VM settings 
  vms.each do |vm|
    config.vm.define vm[:name] do |node|
      node.vm.box = vm[:box]
      node.vm.hostname = vm[:name]
      node.vm.network "private_network", ip: vm[:ip]

      # Virtualbox settings
      node.vm.provider "virtualbox" do |vb|
        vb.memory = 2048 # 2GBS
        vb.cpus = 1
      end


      # SSH configuration for Ansible
      node.vm.provision "shell", inline: <<-SHELL
        # Ensure SSH is configured
        sudo apt-get update && sudo apt-get install -y openssh-server || sudo dnf install -y openssh-server
        sudo systemctl enable sshd
        sudo systemctl start sshd
        # Add vagrant user to sudoers (no password for simplicity)
        echo "vagrant ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/vagrant
        # Ensure vagrant user has SSH keys
        mkdir -p /home/vagrant/.ssh
        chmod 700 /home/vagrant/.ssh
        # Copy the insecure public key (or generate your own)
        #echo "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA6NF8iallvQVp22WDkTkyrtvp9eWW6A8YVr+kz4TjGYe7gHzIw+niNltGEFHzD8+v1I2YJ6oXevct1YeS0o9HZyN1Q9qgCgzUFtdOKLv6IedplqoPkcmF0aYet2PkEDo3Ml0BsOhvEzdqtfkvlN92Er6SfrYxFi3LhF1xflr1cj1q/KDz4Ye0lZxO3bJ6m1uef0ZXtxnf0lygwhA8YVqE9kZ6M9vgT2sY2ZvNUXO0O/0X7m0dPws3yWbfY2nXz3LO0wnX0w2rFUMvVX5SUVIWEN3Ua0Zb3Y0bx6e0wDx8guxyHSxBN2oS45T5gnifV1X3t4s3T+7e0KnE+5kDHo7LduFMkJ4MFCwlI5xqTWlA== vagrant insecure public key" > /home/vagrant/.ssh/authorized_keys
        chmod 600 /home/vagrant/.ssh/authorized_keys
        chown -R vagrant:vagrant /home/vagrant/.ssh
      SHELL
    end
  end

  # Generate Ansible inventory file after all VMs are up
  config.vm.provision "ansible" do |ansible|
    ansible.playbook = "docker-setup/playbook.yml"
    ansible.inventory_path = "inventory"
    ansible.limit = "all"
    ansible.host_key_checking = false
    ansible.extra_vars = {
      ansible_user: "vagrant",
      ansible_ssh_private_key_file: "~/.vagrant.d/insecure_private_key"
    }
  end
end


