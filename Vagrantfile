Vagrant.configure("2") do |config|
config.vm.box_download_insecure = true # prevent ssl certificate in keychain errors on mac 

# Defining the VM
  vms = [
    { name: "debian12", box: "generic/debian12", ip: "192.168.56.10", provider: "virtualbox" },
    { name: "ubuntu2204", box: "generic/ubuntu2204", ip: "192.168.56.11", provider: "virtualbox"  },
    { name: "ubuntu2404", box: "generic/ubuntu2404", ip: "192.168.56.12", provider: "virtualbox"  },
    { name: "rhel8", box: "generic/rhel8", ip: "192.168.56.14", provider: "virtualbox"  },
    { name: "rhel9", box: "genereal/rhel9", ip: "192.168.56.15", provider: "virtualbox"  }
  ]
  # Configure VM settings 
  vms.each do |vm|
    config.vm.define vm[:name] do |node|
      node.vm.box = vm[:box]
      node.vm.hostname = vm[:name]
      node.vm.network "private_network", ip: vm[:ip]

      # Virtualbox settings
      node.vm.provider "virtualbox" do |vb|
        vb.name = vm[:name]
        vb.memory = 1024 # doesnt need to be beefy
        vb.cpus = 1
      end

      # SSH configuration for Ansible
      node.vm.provision "shell", inline: <<-SHELL
        if grep -q "^ID=ubuntu" /etc/os-release; then
          echo "Running on Ubuntu. Performing apt-get update."
          sudo apt-get update && sudo apt-get install -y openssh-server
        elif grep -q "^ID=\"rhel\"" /etc/os-release; then
          echo "Running on RHEL. Performing yum update."
          sudo yum update -y && sudo yum install -y openssh-server
        fi
        
        sudo systemctl enable sshd
        sudo systemctl start sshd
        # Add vagrant user to sudoers (no password for simplicity)
        echo "vagrant ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/vagrant
        # Ensure vagrant user has SSH keys
        mkdir -p /home/vagrant/.ssh
        chmod 700 /home/vagrant/.ssh
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
    ansible.host_vars = {
      "debian12" => {"http_port" => 80},
      "ubuntu2204" => {"http_port" => 80},
      "ubuntu2404" => {"http_port" => 80},
      "rhel8" => {"http_port" => 80},
      "rhel9" => {"http_port" => 80}
    }
    ansible.extra_vars = {
      ansible_user: "vagrant",
    }
    ansible.become = true
  end
end


