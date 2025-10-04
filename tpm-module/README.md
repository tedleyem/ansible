# Ansible TPM module - Manage secrets in TeamPasswordManager
 https://localhost/index.php/install

 This is an internal ansible module for accessing [Team Password Manager](https://teampasswordmanager.com/).
Inspired by [nordsec ansible-tpm](https://github.com/NordSecurity/ansible-tpm)


TPM PYTHON
https://github.com/peshay/tpm/tree/master


### <u>Getting started</u>
You can provide the following information by environment variable or by playbook facts.

|Env Var|Playbook Fact|Description|
|---|---|---|
|TPM_HOST|tpm_hostname|Hostname of you Team Password Manager instance|
|TPM_USER|tpm_username|For Basic authentication: Username|
|TPM_PASS|tpm_password|For Basic authentication: Password|
|TPM_PUBLIC_KEY|tpm_public_key|For HMAC authentication: API Public key|
|TPM_PRIVATE_KEY|tpm_private_key|For HMAC authentication: API Public key|


### TESTING
Use the docker-compose file to spin up TPM locally. Create a user, add a secret.
```
$ docker-compose up -d
```

open your browser and go to https://localhost/index.php/install. O

Once you have a user and password tested you can modify the tpm.ini file to match the credentials you looking for and run the ansible playbook to test connectivity.

##### <u>Why is it local</u>
Team Password manager credentials and options to save credentials and changes don't need to be publicly shared. This is for internal folks who may find it useful for grabbing credentials within a role or playbook. This is geared to help with developmental testing
or automation within an environment without needing ansible galaxy or external factors.


---
# Resources
##### [<u>Creating Ansible Modules</u>](https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_general.html)

##### <u>What is Team Password Manager</u>
Team Password Manager or TPM for short, was created by [Ferran Barba](https://teampasswordmanager.com/about/) and designed to be a group based password manager.

*  [Developing modules](https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_general.html)
* [NordSec ansible-tpm](https://github.com/NordSecurity/ansible-tpm)
