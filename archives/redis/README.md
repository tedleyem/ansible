Redis
=========

This is an Ansible playbook to install redis
Redis Setup 5.0.5

This role is designed to setup a Parent/Child High Availability
cluster with 3 sentinel instances running for a fault tolerant Redis Environment.
* 1 redis master
* 1 redis node
* 1 redis sentinel

## Disclaimer
 This playbook was developed as a POC for testing redis and redis-sentinel
 for caching session history for a web application. Test were done in vagrant
 and have been updated to work with molecule and podman. Changing hosts and inventory
 variables may be required to run properly. But for development purposes, have fun.



Requirements
------------
On RedHat-based distributions, this role requires the EPEL repository.


Role Variables
--------------
There is a large list of configurable variables for setting up redis tha can be found in
vars.yml

The role. Any variables that are read from other roles and/or the global scope (ie. hostvars, group vars, etc.) should be mentioned here as well.

Dependencies
------------
None

Example Playbook
----------------
```
    - hosts: redis
      roles:
         - { role: tedleyem.redis }
```


## Test Setup
This playbook also requires specific host variables
 Example:
 [redis-nodes]
 dolly01 redis_role=master
 dolly02 redis_role=slave
 dolly03 redis_role=sentinel


## Test Playbook
 This playbook can be tested with ansible molecule and/or hashicorp vagrant with the Vagrantfile in the root of the repo.

  Run Molecule
```
  $ molecule init scenario role --driver-name=podman
  $ molecule create

```
  Run Vagrant
```
  $ vagrant provision
```

License
-------

BSD


---
## RESOURCES
[Cache vs Session store ](https://redislabs.com/blog/cache-vs-session-store/)



Author Information
------------------
This role was created in 2018 and recently updated in 2023