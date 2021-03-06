# Name: Chepy
# Website: https://github.com/securisec/chepy
# Description: Decode and otherwise analyze data using this command-line tool and Python library.
# Category: Examine Static Properties: Deobfuscation
# Author: Hapsida Securisec: https://twitter.com/securisec
# License: GNU General Public License (GPL) v3: https://github.com/securisec/chepy/blob/master/LICENSE
# Notes: chepy

include:
  - remnux.packages.python-pip
  - remnux.packages.python3-pip

remnux-python-packages-chepy:
  pip.installed:
    - name: chepy
    - bin_env: /usr/bin/python3
    - require:
      - sls: remnux.packages.python3-pip    

remnux-python-packages-chepy-extras:
  pip.installed:
    - name: chepy[extras]
    - bin_env: /usr/bin/python3
    - watch:
      - pip: remnux-python-packages-chepy