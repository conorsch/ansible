# (c) 2018, Conor Schaefer <conor@freedom.press>
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import subprocess
import yaml


from ansible.errors import AnsibleError


try:
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display
    display = Display()

# All SOPS-encrypted vars files will have a top-level key called "sops".
# In order to determine whether a file is SOPS-encrypted, let's inspect
# such a key if it is found, and expect the following subkeys.
SOPS_EXPECTED_SUBKEYS = [
    "lastmodified",
    "mac",
    "version",
]


class AnsibleSopsError(AnsibleError):
    pass


def is_encrypted_sops_file(file_obj, start_pos=0, count=-1):
    """
    Check whether given filehandle is likely a SOPS-encrypted vars file.
    Determined by presence of top-level 'sops' key in vars file.

    Assumes file is YAML. Does not support JSON files.
    """
    # read the header and reset the file stream to where it started
    current_position = file_obj.tell()
    is_sops_file_result = False
    try:
        file_obj.seek(start_pos)
        y = yaml.safe_load(file_obj.read(count))
        if type(y) == dict:
            # All SOPS-encrypted vars files will have top-level "sops" key.
            if 'sops' in y.keys() and type(y['sops'] == dict):
                if all(k in y['sops'].keys() for k in SOPS_EXPECTED_SUBKEYS):
                    is_sops_file_result = True
    finally:
        file_obj.seek(current_position)

    return is_sops_file_result


def decrypt_sops_file(path):
    """
    Shells out to `sops` binary and reads decrypted vars from stdout.
    Passes back dict to vars loader.

    Assumes that a file is a valid SOPS-encrypted file. Use function
    `is_encrypted_sops_file` to check.

    Assumes file is YAML. Does not support JSON files.
    """
    cmd = ["sops", "--input-type", "yaml", "--decrypt", path]
    real_yaml = None
    try:
        decrypted_yaml = subprocess.check_output(cmd)
    except OSError:
        msg = "Failed to call SOPS to decrypt file at {}".format(path)
        msg += ", ensure sops is installed in PATH."
        raise AnsibleSopsError(msg)
    except subprocess.CalledProcessError:
        msg = "Failed to decrypt SOPS file at {}".format(path)
        raise AnsibleSopsError(msg)
    try:
        real_yaml = yaml.safe_load(decrypted_yaml)
    except yaml.parser.ParserError:
        msg = "Failed to parse YAML from decrypted SOPS file at {},".format(path)
        msg += " confirm file is YAML format."
        raise AnsibleSopsError(msg)
    return real_yaml
