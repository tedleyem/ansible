Ansible Role User-Check 
=========

This playbook simply checks and prints local users on a remote host. 

Requirements
------------
Ansible >= 2.12

Role Variables
--------------
 No specific variables are used here

Dependencies
------------
None

Example Playbook
----------------

---
    - hosts: localhost
      become: yes
      gather_facts: false
      tasks:
        - import_tasks: "tasks/main.yml"


License
-------

BSD

Issues 
------------------
https://github.com/tedleyem/ansible-role-local-user-check/issues


License
------------------
Apache License Version 2.0


Author Information
------------------
https://github.com/tedleyem/