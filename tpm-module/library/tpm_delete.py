#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2024, Tedley Meralus <tmeralus@protonmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
import os
import sys
import traceback
import re
import hmac
import hashlib
import codecs
import json
import time

DOCUMENTATION = r'''
module: tpm_delete
author: Tedley Meralus (@tedleyem)
short_description: Create or modify passwords in TPM
description: This module create or updates password entry in your Team Password Manager instance
version_added: "1.0.0"
options:
    state:
        description: ""
        choices: [present, absent, update]
        type: str
        required: true
    tpm_hostname:
        description: |
            TeamPasswordManager api hostname (ex: my.compagny.com/tpm)
            Fallback to TPM_HOST environment variable if not defined
        type: str
        required: true
    tpm_username:
        description: |
            TeamPasswordManager login for Basic auth
            Fallback to TPM_USER environment variable if not defined
        type: str
    tpm_password:
        description: |
            TeamPasswordManager password for Basic auth
            Fallback to TPM_PASS environment variable if not defined
        type: str
    tpm_public_key:
        description: |
            TeamPasswordManager public key for HMAC auth
            Fallback to TPM_PUBLIC_KEY environment variable if not defined
        type: str
    tpm_private_key:
        description: |
            TeamPasswordManager private key for HMAC auth
            Fallback to TPM_PRIVATE_KEY environment variable if not defined
        type: str
    tpm_ssl_verify:
        description: Validate or not SSL certificates on API connection
        type: bool
        default: true
    name:
        description: Password name
        type: str
        required: true
    project_name:
        description: Project name
        type: str
    tags:
        description: Tag list
        type: list
        elements: str
    access_info:
        description: Url
        type: str
    username:
        description: Username
        type: str
    email:
        description: email
        type: str
    password:
        description: If not defined, the value is generated with Team Password Manager api
        type: str
    expiry_date:
        description: "Expiration date (fmt: mm-dd-yyyy)"
        type: str
    notes:
        description: Free text note
        type: str
'''

EXAMPLES = r'''

'''

RETURN = r'''
tpm:
    description: ''
    returned: success
    type: complex
    contains:
        id:
            description: Internal ID of the password entry
            returned: success
            type: int
            sample: 1234
        name:
            description: Name of the password entry
            returned: success
            type: str
        project:
            description: Project
            returned: success
            type: complex
            contains:
                id:
                    description: Project ID
                    returned: success
                    type: int
                    sample: 1234
                name:
                    description: Project name
                    returned: success
                    type: str
        tags:
            description: Tag list (comma separated)
            returned: success
            type: str
        access_info:
            description: Url
            returned: success
            type: str
        username:
            description: Username
            returned: success
            type: str
        email:
            description: email
            returned: success
            type: str
        password:
            description: Password value
            returned: success
            type: str
        expiry_date:
            description: Expiry date
            returned: success
            type: str
        expiry_status:
            description: 'has the following values: 0=no date or not expired, 1=expires today, 2=expired, 3=will expire soon'
            returned: success
            type: int
        notes:
            description: Notes
            returned: success
            type: str
        custom_fieldN:
            description: Custom field
            returned: success
            type: complex
            contains:
                type:
                    description: Can be one of 'Text', 'Encrypted text', 'E-mail' or 'email, 'Password', 'Notes', 'Encrypted notes'
                    returned: success
                    type: str
                label:
                    description: Custom type label
                    returned: success
                    type: str
                data:
                    description: Custom type data
                    returned: success
                    type: str
        archived:
            description: Archived
            returned: success
            type: bool
        locked:
            description: Locked
            returned: success
            type: bool
        created_on:
            description: Creation date
            returned: success
            type: str
        updated_on:
            description: Last update date
            returned: success
            type: str
'''

# API CRUD CLASSES
try:
    from urllib import quote        # Python 2.x
except ImportError:
    from urllib.parse import quote  # Python 3+

from ansible.module_utils.urls import open_url
from ansible.module_utils.common.dict_transformations import dict_merge

class OpenUrlError(Exception):
    """Failed to open given url"""

class GenerateError(Exception):
    """Generate call to TPM api failed"""

class GetError(Exception):
    """Get call to TPM api failed"""

class FindError(Exception):
    """Find call to TPM api failed"""

class CreateError(Exception):
    """Create call to TPM api failed"""

class UpdateError(Exception):
    """Update call to TPM api failed"""

class DeleteError(Exception):
    """Delete call to TPM api failed"""

class TpmApiBase():
    """Base class for REST queries to TPM

    Raises:
        OpenUrlError: Failed to HTTP GET
        OpenUrlError: Failed to HTTP POST
        OpenUrlError: Failed to HTTP PUT
        OpenUrlError: Failed to HTTP DELETE

    Returns:
        json: API resposne
    """

    @staticmethod
    def default_headers():
        return {
            "Content-Type": "application/json; charset=utf-8",
        }

    @staticmethod
    def default_config():
        return {
            'tpm_ssl_verify': True,
        }

    def __init__(self, config = None):
        self.config = dict_merge(TpmApiBase.default_config(), config or {})

        # Determine which login method to use
        if all([config.get('tpm_public_key', None),
                config.get('tpm_private_key', None)]):
            self.config['use_hmac'] = True
            self.config.pop('tpm_username')
            self.config.pop('tpm_password')

    def __get_headers(self, path, data = None):
        if self.config.get('use_hmac', False):
            timestamp = str(int(time.time()))
            msg_data = [path, timestamp] + ([json.dumps(data)] if data else [])
            headers = dict_merge(TpmApiBase.default_headers(), {
                "X-Public-Key": self.config.get('tpm_public_key'),
                "X-Request-Hash": self.__sha256_signature(''.join(msg_data)),
                "X-Request-Timestamp": timestamp,
            })
            return headers
        # Else, return default headers
        return TpmApiBase.default_headers()

    def __sha256_signature(self, msg):
        key = self.config.get('tpm_private_key')

        return hmac.new(
            digestmod=hashlib.sha256,
            key=codecs.encode(key),
            msg=codecs.encode(msg),
        ).hexdigest()

    def __get_url(self, path):
        return 'https://{host}/index.php/{path}'.format(
            host=self.config.get('tpm_hostname'),
            path=path
        )

    def _http_get(self, path):
        r = open_url(self.__get_url(path), method='GET',
                     headers=self.__get_headers(path),
                     url_username=self.config.get('tpm_username', None),
                     url_password=self.config.get('tpm_password', None),
                     force_basic_auth='tpm_username' in self.config,
                     validate_certs=self.config.get('tpm_ssl_verify'),
                     )

        if r.status == 200:
            try:
                next_page_link = r.getHeader('Link', default=None)
                if next_page_link:
                    matcher = re.search('<https://.+/index.php/(.+)>; rel="next"', next_page_link)
                    next_page = self._http_get(matcher.group(1))

                return json.load(r) + next_page if next_page else json.load(r)

            except Exception:
                return json.loads(r)

        raise OpenUrlError('HTTP {s} - Failed to GET data'.format(s=r.status))

    def _http_post(self, path, body = None):
        r = open_url(self.__get_url(path), method='POST',
                     headers=self.__get_headers(path, data=body),
                     data=body,
                     url_username=self.config.get('tpm_username', None),
                     url_password=self.config.get('tpm_password', None),
                     force_basic_auth='tpm_username' in self.config,
                     validate_certs=self.config.get('tpm_ssl_verify'),
                     )

        if r.status == 201:
            return json.load(r)

        raise OpenUrlError('HTTP {s} - Failed to POST data'.format(s=r.status))

    def _http_put(self, path, body = None):
        r = open_url(self.__get_url(path), method='PUT',
                     headers=self.__get_headers(path, data=body),
                     data=body,
                     url_username=self.config.get('tpm_username', None),
                     url_password=self.config.get('tpm_password', None),
                     force_basic_auth='tpm_username' in self.config,
                     validate_certs=self.config.get('tpm_ssl_verify'),
                     )

        if r.status == 204:
            return {}

        raise OpenUrlError('HTTP {s} - Failed to PUT data'.format(s=r.status))

    def _http_delete(self, path):
        r = open_url(self.__get_url(path), method='DELETE',
                     headers=self.__get_headers(path),
                     url_username=self.config.get('tpm_username', None),
                     url_password=self.config.get('tpm_password', None),
                     force_basic_auth='tpm_username' in self.config,
                     validate_certs=self.config.get('tpm_ssl_verify'),
                     )

        if r.status == 204:
            return {}

        raise OpenUrlError('HTTP {s} - Failed to DELETE data'.format(s=r.status))


class TpmPasswordApi(TpmApiBase):
    """TPM Password API implementation"""

    def getById(self, id = 0):
        '''
        Return data found from TPM for the given ID
        '''
        try:
            return self._http_get(path='api/v4/passwords/{id}.json'.format(id=id))
        except Exception as e:
            raise GetError(e)

    def find(self, query_str = ''):
        '''
        Return data found from TPM for the given query string
        '''
        try:
            return self._http_get(
                path='api/v4/passwords/search/{q}.json'.format(
                    q=quote(query_str.encode('utf-8'))),
            )
        except Exception as e:
            raise FindError(e)

    def findFirst(self, query_str = '', default=None):
        '''
        Return first find result
        '''
        return next((i for i in self.find(query_str)), default)

    def generate(self):
        '''
        Return new generated password from TPM
        '''
        try:
            return self._http_get(path='api/v4/generate_password.json')
        except Exception as e:
            raise GenerateError(e)

    def create(self, project_name, name,
               tags = None,
               access_info = None,
               username = None,
               email = None,
               password = None,
               expiry_date = None,
               notes = None,
               ):
        '''
        Return newly created password
        '''
        project_api = TpmProjectApi()
        project = project_api.findFirst(project_name)

        data = dict(
            project_id=project.id,
            name=name,
            tags=','.join(tags),
            access_info=access_info,
            username=username,
            email=email,
            password=password or self.generate()['password'],
            expiry_date=expiry_date,
            notes=notes,
        )

        try:
            r = self._http_post(
                path='api/v4/passwords.json',
                body=data
            )
            return self.getById(r['id'])

        except Exception as e:
            raise CreateError(e)

    def update(self, id, name,
               tags = None,
               access_info = None,
               username = None,
               email = None,
               password = None,
               expiry_date = None,
               notes = None,
               ):
        '''
        Return updated password
        '''
        entry = self.getById(id)

        data = dict(
            name=name or entry.get('name'),
            tags=','.join(set(entry.get('tags').split(',') + tags)),
            access_info=access_info or entry.get('access_info'),
            username=username or entry.get('username'),
            email=email or entry.get('email'),
            password=password or self.generate().get('password'),
            expiry_date=expiry_date or entry.get('expiry_date'),
            notes=notes or entry.get('notes'),
        )

        try:
            self._http_put(
                path='api/v4/passwords/{id}.json'.format(id=id),
                body=data
            )
            return self.getById(id)

        except Exception as e:
            raise UpdateError(e)

class TpmProjectApi(TpmApiBase):
    """TPM Project API implementation"""

    def getById(self, id):
        '''
        Return data found from TPM for the given ID
        '''
        try:
            return self._http_get(path='api/v4/projects/{id}.json'.format(id=id))
        except Exception as e:
            raise GetError(e)

    def find(self, query_str=''):
        '''
        Return data found from TPM for the given query string
        '''
        try:
            return self._http_get(
                path='api/v4/projects/search/{q}.json'.format(
                    q=quote(query_str.encode('utf-8')))
            )
        except Exception as e:
            raise FindError(e)

    def findFirst(self, query_str='', default=None):
        '''
        Return first find result
        '''
        return next((i for i in self.find(query_str)), default)

    def create(self, name, parent_id, tags = None, notes = None):
        '''
        Return newly created project
        '''
        tags = tags or []
        data = dict(
            name=name,
            parent_id=parent_id,
            tags=','.join(tags),
            notes=notes,
        )

        try:
            r = self._http_post(
                path='api/v4/projects.json',
                body=data
            )
            return self.getById(r['id'])

        except Exception as e:
            raise CreateError(e)

    def update(self, id, name, tags = None, notes = None):
        '''
        Return updated project
        '''
        tags = tags or []
        entry = self.getById(id)

        data = dict(
            name=name,
            tags=','.join(set(entry.get('tags', '').split(',') + tags)),
            notes=notes or entry.get('notes')
        )

        try:
            r = self._http_put(
                path='api/v4/projects/{id}.json'.format(id=id),
                body=data
            )
            return self.getById(r['id'])

        except Exception as e:
            raise CreateError(e)

    def delete(self, id):
        '''
        Delete specified project
        '''
        try:
            self._http_delete(
                path='api/v4/projects/{id}.json'.format(id=id)
            )
            return "Successfully deleted project"

        except Exception as e:
            raise DeleteError(e)

# END API CRUD CLASSES

# BASE MODULE
from ansible.module_utils.basic import (
    AnsibleModule,
    env_fallback,
)
from ansible.module_utils.common.dict_transformations import dict_merge

# from .api import TpmApiBase, FindError

class AlreadyExistsError(Exception):
    """Creation failed. Item already exists"""

class StateNotImplementedError(Exception):
    """Specified state is not implemented"""

class TpmModuleBase(AnsibleModule):
    """TPM Module base implementation"""

    __arg_spec_base: dict = dict(
        # Expected state
        state=dict(
            type='str',
            choices=['present', 'absent', 'update'],
            required=True,
        ),
        # Api connection informations
        tpm_hostname=dict(
            type='str',
            required=True,
            fallback=(env_fallback, ['TPM_HOST']),
        ),
        tpm_ssl_verify=dict(
            type='bool',
            required=False,
            default=True,
        ),
        # Basic auth
        tpm_username=dict(
            type='str',
            fallback=(env_fallback, ['TPM_USER']),
        ),
        tpm_password=dict(
            type='str',
            fallback=(env_fallback, ['TPM_PASS']),
            no_log=True,
        ),
        # HMAC auth
        tpm_public_key=dict(
            type='str',
            fallback=(env_fallback, ['TPM_PUBLIC_KEY']),
        ),
        tpm_private_key=dict(
            type='str',
            fallback=(env_fallback, ['TPM_PRIVATE_KEY']),
            no_log=True,
        ),
    )
    __mutually_exclusive: list = [
        ('tpm_username', 'tpm_public_key'),
        ('tpm_password', 'tpm_private_key'),
    ]
    __required_together: list = [
        ('tpm_username', 'tpm_password'),
        ('tpm_public_key', 'tpm_private_key'),
    ]
    __required_one_of: list = [
        ('tpm_username', 'tpm_public_key'),
        ('tpm_password', 'tpm_private_key'),
    ]

    def __init__(self,
                 argument_spec=None,
                 bypass_checks=False,
                 no_log=False,
                 mutually_exclusive=None,
                 required_together=None,
                 required_one_of=None,
                 add_file_common_args=False,
                 supports_check_mode=False,
                 required_if=None,
                 required_by=None):
        argument_spec = argument_spec or {}
        required_by = required_by or {}
        mutually_exclusive = mutually_exclusive or []
        required_together = required_together or []
        required_one_of = required_one_of or []

        argument_spec = dict_merge(TpmModuleBase.__arg_spec_base, argument_spec)
        mutually_exclusive.extend(TpmModuleBase.__mutually_exclusive)
        required_together.extend(TpmModuleBase.__required_together)
        required_one_of.extend(TpmModuleBase.__required_one_of)

        super().__init__(
            argument_spec,
            bypass_checks=bypass_checks,
            no_log=no_log,
            mutually_exclusive=mutually_exclusive,
            required_together=required_together,
            required_one_of=required_one_of,
            add_file_common_args=add_file_common_args,
            supports_check_mode=supports_check_mode,
            required_if=required_if,
            required_by=required_by
        )

        self.config = dict_merge(TpmApiBase.default_config(), {
            'tpm_hostname': self.params.get('tpm_hostname'),
            'tpm_public_key': self.params.get('tpm_public_key'),
            'tpm_private_key': self.params.get('tpm_private_key'),
            'tpm_username': self.params.get('tpm_username'),
            'tpm_password': self.params.get('tpm_password'),
            'tpm_ssl_verify': self.params.get('tpm_ssl_verify'),
            'use_hmac': all(['tpm_public_key' in self.params, 'tpm_private_key' in self.params]),
        })

    def run(self):
        """Run create/update actions"""
        fn = {
            'present': self.fn_present,
            'absent': self.fn_absent,
            'update': self.fn_update,
        }.get(self.params.get('state', self.fn_default))

        try:
            r = fn()

        except AlreadyExistsError as e:
            self.exit_json(
                changed=False,
                result={'tpm': e.args}
            )

        except Exception as e:
            self.fail_json(
                changed=False,
                error=str(e),
                stacktrace=traceback.format_exc().splitlines(),
            )

        else:
            self.exit_json(
                changed=True,
                result={'tpm': r},
            )

    def fn_default(self) -> dict:
        raise StateNotImplementedError()

    def fn_present(self) -> dict:
        data: dict = self.params.get('data', {})

        try:
            # First find existing secret with the verysame name
            item = self.findFirst(data.get('name'), default=None)

        except FindError:
            return self.create(**data)

        else:
            raise AlreadyExistsError(item)

    def fn_absent(self) -> dict:
        data: dict = self.params.get('data', {})

        try:
            # First find existing secret with the verysame name
            item = self.findFirst(data.get('name'), default=None)

        except FindError as e:
            raise e

        else:
            return self.delete(item['id'])

    def fn_update(self) -> dict:
        data: dict = self.params.get('data', {})

        try:
            # First find existing secret with the verysame name
            item = self.findFirst(data.get('name'), default=None)

        except FindError as e:
            raise e

        else:
            return self.update(item['id'], **data)

class TpmLookupBase():
    """TPM Lookup Module base implementation"""

    @staticmethod
    def task_keys(variables):
        keys = {
            'hostname': 'TPM_HOST',
            'public_key': 'TPM_PUBLIC_KEY',
            'private_key': 'TPM_PRIVATE_KEY',
            'username': 'TPM_USER',
            'password': 'TPM_PASS',
        }
        return {k: variables.get('tpm_{k}'.format(k=k), os.getenv(v)) for k, v in keys.items()}

# END BASE MODULE

class TpmModule(TpmModuleBase, TpmPasswordApi):
    pass

def main():
    TpmModule(
        argument_spec=dict(
            name=dict(type='str', required=True),
            project_name=dict(type='str', required=True),
            tags=dict(type='list', default=[], elements='str'),
            access_info=dict(type='str', default=None),
            username=dict(type='str', default=None, required=True),
            email=dict(type='str', default=None),
            password=dict(type='str', default=None, no_log=True, required=True),
            expiry_date=dict(type='str', default=None),
            notes=dict(type='str', default=None),
        ),
        required_if=[
            ('state', 'present', ('name', 'project_name', 'tpm_hostname', 'tpm_username', 'tpm_password')),
            ('state', 'absent', ('name',)),
            ('state', 'update', ('name',)),
        ],
        supports_check_mode=False,
    ).run()


if __name__ == "__main__":
    main()
