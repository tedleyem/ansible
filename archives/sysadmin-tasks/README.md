# Ansible Sysadmin Taks 

A list of sysadmin tasks to use for Ansible Tower (automation platform)
or with ansible cli. This list has and will grow over time. 

### Structure
This structure is not the conventional structure for 
a typical ansible role. However, this can be used as a baseline 
for creating Ansible Projects and Template in Ansible Automation Platform/ Ansible Tower. 

```
.
└── inventory <-- local inventory to use for testing these playbooks and roles 
├── playbooks <-- the directory containing the sysadmin tasks 
│   ├── security <-- the directory where you can find a few exploit checks 
├── README.md
├── roles <-- A few roles that can be used for mixed systems
├── templates <-- Template files used for playbooks
└── test <-- Dockerfiles for Ansible test provisioning with Vagrant
└── vars
    └── main.yml
└── Vagrantfile <-- Vagrantfile used for testing playbooks

    ```
 
---
## Setup

##### Create new role
 To create a new role you can run the following commands 
```
$ ansible-galaxy role init roles/<role-name>
```
To remove ansbile-galaxy meta tags 
```
$ rm -rf <role-name>/meta
```

## Vagrant Local Development
To test these out locally you can run the Vagrantfile 
in the root of this project. 

The Vagrantfile uses [docker](https://developer.hashicorp.com/vagrant/docs/providers/docker/basics) as the provider.
Once installed with virtualbox set the provider and run. 
```
$ vagrant up --provider=docker
```

## Why Vagrant with Docker?

 This was inspired by Apple's introduction of the M1 chip which is ARM based. That means that testing solutions which use Vagrant and VirtualBox don't work on Apple M1 because VirtualBox requires an Intel processor. This triggered a search and solution for a virtual development environment that works with ARM and thus Apple M1 computers.  

[Docker](https://www.docker.com) has introduced [Docker Desktop for Apple silicon](https://docs.docker.com/docker-for-mac/apple-silicon/) that runs Docker on Macs that have the Apple M1 chip. By using Docker as a provisioner for Vagrant, you can simulate the same experience as developers using Vagrant with VirtualBox. This is one case where you actually do want a Docker container to behave like a VM.
