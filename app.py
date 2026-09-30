# TESTING WINDOWS AD
import sys
from ldap3 import Server, Connection, ALL, SIMPLE, NTLM, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, AUTO_BIND_NO_TLS, SUBTREE
from ldap3.core.exceptions import LDAPException,LDAPBindError,LDAPCursorError,LDAPAttributeError

def winAd(domainUser, password, serverIpOrFqdn, domainSuffix):
  user_principal = f"{domainUser}@{domainSuffix}"
  try:
    server = Server(serverIpOrFqdn, get_info=ALL)
    connection = Connection(
      server,
      user='{}\\{}'.format(domainSuffix, domainUser),
      password=password,
      authentication=NTLM, # SIMPLE or NTLM
      # raise_exceptions=True
      auto_bind=True
    )
    connection.bind()

    # print(server.info) # Server info
    # conn=connection.extend.standard.who_am_i() # Get login name
    # print(connection) # Print connection

    # Get list of active directory
    connection.search(
      search_base='dc={},dc=local'.format(domainSuffix),
      search_filter='(objectclass=person)',
      attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES]
    )

    print(connection.info)

    sortedEntries=sorted(connection.entries,key=lambda e:e.entry_dn)

    for c in sortedEntries:
      print(c)
      try:
        desc = c.description
      except LDAPCursorError:
        desc = ""
      print(str(c.name))


    connection.unbind()
    return True, "success"

  except LDAPBindError as e:
    error_msg=e
    return False,error_msg
  except LDAPException as e:
    error_msg=e
    return False, error_msg

success, message = winAd('Username', 'Password', 'IP or target machine', 'Domain')
print(f"Status: {success}")
print(f"Detail: {message}")
