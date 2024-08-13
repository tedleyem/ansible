# ansible-role-nagios-docker
ansible role to spin up nagios in a docker container
Docker image for Nagios
Nagios Core 4.4.5 running on Ubuntu 16.04 LTS with NagiosGraph & NRPE

## Run with Ansible
 ansible-playbook roles/ansible-role-nagios-docker/nagios_docker_server.yml

## Run manually
docker run -d --privileged --name nagios -v /:/configs/overlay/opt -p 80:80 -p 5666:5666 <user-name>/nagios:latest

#### Credentials
The default credentials for the web interface is `nagiosadmin` / `nagios`
