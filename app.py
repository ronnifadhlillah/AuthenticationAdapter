# TESTING WINDOWS AD
import sys
from ldap3 import Server, Connection, ALL, SIMPLE, NTLM, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, AUTO_BIND_NO_TLS, SUBTREE
from ldap3.core.exceptions import LDAPException,LDAPBindError,LDAPCursorError,LDAPAttributeError
from adapter.strategy import Strategy

s=Strategy.winAd2('Username', 'Password', 'IP or target machine', 'Domain')
success, message = s
print(f"Status: {success}")
print(f"Detail: {message}")
