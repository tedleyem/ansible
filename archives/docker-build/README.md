# Ansible Role Docker Build
Ansible role to build a docker container locally,
then push the new container to docker hub.

## Important Variables
There are specific variables that do the following
dockerhub_name: Used to login to docker registry
dockerhub_password: password for dockerhub registrsy login

- dock_ubuntu_image: base image for Ubuntu
- dock_centos_image: base image for CentOS
- local_container_name: name of container being saved and pushed to dockerhub

- ansible_keypair: ansible user key to add to docker container if created

- local_user_keypair: user running ansible playbook public key to add to docker container if found or created



This ansible playbook does the following   
- installs pyhthon based docker and docker related packages
- creates a docker file with previously configured ansible ssh key if found
- setup a docker container that ansible can penetrate.
- connects to dockerhub
- checks for docker dev container
- if not found creates a dev container
- pushes dev container to dockerhub
