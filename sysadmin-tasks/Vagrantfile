Vagrant.configure("2") do |config|
  # Fix for container creation timeout connection loop
  config.vm.boot_timeout = 5

  config.vm.define "ubuntu" do |ubuntu|
    ubuntu.vm.provider "docker" do |docker|
      docker.vagrant_vagrantfile = "tests/host/Vagrantfile"
      docker.name = "dev-ubuntu"
      # To build from a Dockerfile in test dir
      # comment out docker.image and uncomment docker.build line
      #docker.image = "ubuntu:20.04"
      docker.build_dir = "tests/docker/ubuntu/focal-2004/"
      docker.remains_running = true
      docker.has_ssh = true
      docker.privileged = true
      docker.volumes = ["/sys/fs/cgroup:/sys/fs/cgroup:rw"]
      # Uncomment to force arm64 for testing images on Intel
      # docker.create_args = ["--platform=linux/arm64"]     
    end
  end 

  config.vm.define "rhel" do |rhel|
    rhel.vm.provider "docker" do |docker|
      docker.vagrant_vagrantfile = "tests/host/Vagrantfile"
      docker.name = "dev-rhel8"
      # To build from a Dockerfile in test dir
      # comment out docker.image and uncomment docker.build line
      #docker.image = "debian:bullseye"
      docker.build_dir = "tests/docker/redhat/rhel8/"
      docker.remains_running = true
      docker.has_ssh = true
      docker.privileged = true
      docker.volumes = ["/sys/fs/cgroup:/sys/fs/cgroup:rw"]
      # Uncomment to force arm64 for testing images on Intel
      # docker.create_args = ["--platform=linux/arm64"]     
    end
  end

  config.vm.provision "ansible" do |ansible| 
    ansible.verbose = "v"
    ansible.inventory_path = "tests/inventory.yml"
    ansible.groups = {
      "group" => ["vagrant"],
    } 
    # Mention the fully qualified path and name of playbook. 
    # If no path mentioned, vagrant will take the base directory where Vagrantfile resides  
    ansible.playbook="playbooks/main.yml" 
  end  

end
