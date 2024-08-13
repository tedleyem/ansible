# ansible-role-docker-jenkins
 ansible role used to install Jenkins with docker on dedicated server

 ## Prerequisites
 This module has a few dependencies:

 - [Ansible2.8](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html)
 - [Python](https://www.python.org/downloads)
 - [Docker](https://docs.docker.com/install/linux/docker-ce/ubuntu)
 - [Jenkins Playbook](https://github.com/<user-name>/ansible-role-docker-jenkins.git)

 ## What Includes

 Followiing things includes in this role:
 - jenkins

 ## Example Playbook

 **IMPORTANT:** Since the `master` branch used in `source` varies based on new modifications, I suggest that you use the release versions [here](https://github.com/<user-name>/ansible-role-docker-jenkins.git/releases).

 ```yaml
 - hosts: localhost
   remote_user: root
   become: true
   roles:
     - <user-name>.ansible_role_docker_jenkins
 ```

 ## Variables

 ```yaml
   jenkins_version: "lts-alpine"
   jenkins_server_name: jenkins.<user-name>.com
   jenkins_opt_dir: "/opt/jenkins"
   jenkins_config_dir: "{{ jenkins_opt_dir }}/config"
   jenkins_tmp_dir: "{{ jenkins_opt_dir }}/tmp"
   jenkins_data_dir: "{{ jenkins_opt_dir }}/data"
   jenkins_https_port: "443"
   jenkins_http_port: "8080"
   jenkins_xmx: "{{ ( ansible_memtotal_mb * 0.20 ) | round(0, 'ceil') | int }}"
   jenkins_user: jenkins
   jenkins_group: jenkins
   jenkins_hostname: localhost
   jenkins_agent_port: "50001"
   jenkins_plugins:
     - git
     - ssh
   cert_path: "/root/config/star-<user-name>.crt"
   key_path: "/root/config/<user-name>-sub-domain-private-key.pem"
 ```

 ## Installation

 ```console
   $ ansible-galaxy install <user-name>.ansible_role_docker_jenkins
 ```
