# TESTING WINDOWS AD
import ssl
from ldap3 import Server, Connection, ALL, SIMPLE
from ldap3.core.exceptions import LDAPException,LDAPBindError

def winAd(domainUser, password, serverIpOrFqdn, domainSuffix):
  user_principal = f"{domainUser}@{domainSuffix}"
  try:
    server = Server(serverIpOrFqdn, get_info=ALL)
    connection = Connection(
      server,
      user=user_principal,
      password=password,
      authentication=SIMPLE,
      raise_exceptions=True
    )
    connection.bind()
    connection.unbind()
    return True, "success"

  except LDAPBindError as e:
    error_msg=e
    return False,error_msg
  except LDAPException as e:
    error_msg=e
    return False, error_msg

success, message = winAd('username', 'password', 'IP or machine name', 'domain')
print(f"Status: {success}")
print(f"Detail: {message}")