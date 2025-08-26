Ansible Template
================

This repository is a boilerplate for spinning up new ansible roles and playbooks. 
Created because of Ansibles ideas on creating an ansible-playbook init

Requirements
------------
* ansible 
* vagrant
* docker



## Command Line Usage

To use this provider, add the `--provider` flag to your `vagrant` command:

```sh
vagrant up --provider=docker
```
## Why Vagrant with Docker?

 This was inspired by Apple's introduction of the M1 chip which is ARM based. That means that solutions which use Vagrant and VirtualBox will not work on Apple M1 because VirtualBox requires an Intel processors. This lead me to find a solution for a virtual development environment that works with ARM and thus Apple M1 computers. You can find out more information about why I built it here:


[Docker](https://www.docker.com) has introduced [Docker Desktop for Apple silicon](https://docs.docker.com/docker-for-mac/apple-silicon/) that runs Docker on Macs that have the Apple M1 chip. By using Docker as a provisioner for Vagrant, we can simulate the same experience as developers using Vagrant with VirtualBox. This is one case where you actually do want a Docker container to behave like a VM.


License
-------

BSD

Author Information
------------------

An optional section for the role authors to include contact information, or a website (HTML is not allowed).


Credits 
-------

* [mcwarman](https://github.com/mcwarman/vagrant-docker-provider/tree/master) - the guy who inspired the vagrantfiles and docker images
*
