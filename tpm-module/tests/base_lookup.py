# -*- coding: utf-8 -*-
# (c) 2024, Tedley Meralus <tmeralus@protonmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os

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
