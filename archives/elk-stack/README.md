# Deprecated 
# This repo is archived and hasnt been maintained or tested in quite some time. 
# consider finding another solution

# ansible-elasticsearch
An ansible playbook that installs elasticsearch 7.0.0

## Requirements
This playbook prompts for Session or Cache cluster
This only affects the parameters saved in the redis.conf file.

Cache Cluster: saves redis data in memory (normal behavior in an LRU/Memcached setup)
Session Cluster: saves data on disk (Setup for using Redis as a Sesssion store)


## Role Variables
### all variables can be found in the defaults/main.yml
## specific vars for elasticsearch names are in the playbook.yml file #
{% for host in groups['elk'] %}
{% if hostvars[host]['elk_role'] == 'master' %}
network.host: {{ hostvars[host]['ansible_default_ipv4']['address'] }}
{% endif %}
{% endfor %}

## Dependencies

## Test Playbook
 ansible-playbook -i inventory/local -l elk ansible-role-elk-stack/elk.yml

 Inventory group should be labeled as [elk]
 Example:
 [elk]
 dolly01

License
GNU GPLv3


Author Information
 Twitter: @TechGameTeddy
