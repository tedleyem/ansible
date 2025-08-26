UPDATE-NAGIOS Playbook
========

## Description
 Ansible playbook to update preexisting configs and restart Nagios Monitoring server
 Used as a step to automate Nagios
 nagios host files and configuration settings in the configs dir of playbook

## Requirements - ROLES
- Linux host with default Nagios configuration parameters set.

## Deploy Playbook
 This command can be run from the /home/ansible/ansible dir on ansible.company.com server

  ansible-playbook -i inventory/networking roles/updatenagios/update.yml
