Memcached-Setup
=========

ansible-role-memcache-setup


Requirements

This playbook has a setup task that installs Devlopment Tools
on RedHat/CentOS Based distros are found

Role Variables
  Memcache Port 2 and 3 can be coomented/uncommented in each OS-specificed var file
  to add multiple instances of memcached on the same server

  memcached_port: '666'
  memcached_port2: '888'
  memcached_port3: '999'
  memcached_listen_ip: 127.0.0.1
  memcache_version: "memcached-1.5.15"
  memcache_url: "http://www.memcached.org/files/{{ memcache_version }}.tar.gz"
  memcache_dir: "/opt/{{ memcache_version }}"
  install_dir: "/tmp/{{ memcache_version }}"
  memcached_user: root
  memcached_config_file: /etc/sysconfig/memcached
  memcached_memory_limit: '2048'
  memcached_connections: '2048'
  memcached_cache: '2048'

Dependencies
------------
 glibc and cmake tools are required to install memcached from souces.


Test Playbook

 ansible-playbook -i inventory/local
 roles/memcache/main.yml

License
GNU GPLv3


Author Information
 Twitter: @TechGameTeddy
