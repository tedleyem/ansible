# ANSIBLE-DOCKER-SETUP-PLAYGROUND
=========

This simply provisions docker containers and installs docker
onto a system.

Used for confirming docker is running and installed properly on a system.

Note: An inventory file "local" is added for development purposes
------------


DEPENDENCIES

REQUIREMENTS
--Docker   
--Ansible


REMINDER
Docker should be running a process in the foreground in your container and will be spawned as PID 1 within the container's pid namespace.
Docker is designed for process isolation, not for OS virtualization, so there are no OS processes and daemons running inside the container (like systemd, cron, syslog, etc), only your entrypoint or command you run.
