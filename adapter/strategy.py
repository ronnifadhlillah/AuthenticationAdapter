from ldap3 import Server, Connection, ALL, SIMPLE, NTLM, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, AUTO_BIND_NO_TLS, SUBTREE
from ldap3.core.exceptions import LDAPException,LDAPBindError,LDAPCursorError,LDAPAttributeError
import adapter
import ldap
import imaplib
import os
import socket
import tldextract
import sys
import re



class Strategy:
    def __init__(self,uri,un,ps,prt):
        self.uri=uri
        self.un=un
        self.ps=ps
        self.prt=prt
        self.dc=self.uri.split('.')
        # OLD : if (Strategy.DomainValidate(self))==False:
        if not self.DomainValidate():
            print('Something wrong with your parameter. Check it out')
            sys.exit()

    def Imap(self):
        if tldextract.extract(self.uri).subdomain is not '':
            username='%s@%s'%(self.un,'.'.join(self.dc[1:]))

        imp=None
        try:
            imp=imaplib.IMAP4_SSL(self.uri,port=self.prt)
            imp.login(username,self.ps)
            return True
        except imaplib.IMAP4.error:
            return False
        finally:
          if imp:
              try:
                imp.logout()
              except:
                pass

    def SmbAD(self):
        if tldextract.extract(self.uri).subdomain is not '':
            username='%s@%s' % (self.un,'.'.join(self.dc[1:]))
            dn=[]
            for i in dc[1:]:
                dn.append(str(i))
        else:
            username='%s@%s' % (self.un,'.'.join(self.dc[0:]))
            dn=[]
            for i in dc[0:]:
                dn.append(str(i))
        # Mastering DN
        bj=',DC='.join(dn)
        base_dn=str('DC='+bj)
        return Strategy.doAuthentication(self,username,base_dn,dn)

    def WinAD1(self):
        username='%s@%s' % (self.un,'.'.join(self.dc[1:]))
        dc=self.uri.split('.')
        if tldextract.extract(self.uri).subdomain is not '':
            username='%s@%s' % (self.un,'.'.join(dc[1:]))
            dn=[]
            for i in dc[1:]:
                dn.append(str(i))
        else:
            username='%s@%s' % (self.un,'.'.join(dc[0:]))
            dn=[]
            for i in dc[0:]:
                dn.append(str(i))
        # Mastering DN
        bj=',DC='.join(dn)
        base_dn=str('DC='+bj)
        return Strategy.doAuthentication(self,username,base_dn,dn)

    def winAd2(domainUser, password, serverIpOrFqdn, domainSuffix):
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

        # Get list of active directory
        connection.search(
          search_base='dc={},dc=local'.format(domainSuffix),
          search_filter='(objectclass=person)',
          attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES]
        )

        print(connection.info)

        sortedEntries=sorted(connection.entries,key=lambda e:e.entry_dn)

        for c in sortedEntries:
          try:
            desc = c.description
          except LDAPCursorError:
            desc = ""
      # print(str(c.name))
      
        connection.unbind()
        return True, "success"

      except LDAPBindError as e:
        error_msg=e
        return False,error_msg
      except LDAPException as e:
        error_msg=e
        return False, error_msg

    def DomainValidate(self):
      # Validation URI parameter
      # uri contain number
      # Validation if input using IP as Domain Controller , it's not recommend
      if self.uri.replace('.','').isnumeric() == True:
        return False
      # uri contain http://,https://,www.
      pattern=re.match('((http|https)://)(www.)?[a-zA-Z0-9@:%._\\+~#?&//=]{2,256}\\.[a-z]{2,6}\\b([-a-zA-Z0-9@:%._\\+~#?&//=]*)',self.uri)
      # OLD : if bool(pattern) == True:
      #     return False
      if pattern:
        return False
      return True

    def doAuthentication(self,username,base_dn,dn):
      # OLD : addr=socket.gethostbyname(self.uri.upper())
      # l=ldap.initialize('ldap://%s' % addr)
      # l.protocol_version=ldap.VERSION3
      # l.set_option(ldap.OPT_REFERRALS,self.prt)
      # try:
      #     l.simple_bind_s(username,self.ps)
        # # LDAP testing below is currently running on linux (smb4DAD only)
        # attr=['Domain'] #--> For testing the AD
        # # # testing ldap connection --> For testing the AD
        # auth=l.search_s(base_dn,ldap.SCOPE_SUBTREE,'(objectClass=*)',attr) #--> For testing the AD
        # for dn,entry in auth: #--> For testing the AD
        #     print('Processing',repr(entry)) #--> For testing the AD
      #     return True
      # except ldap.INVALID_CREDENTIALS:
      #     return False
      
      try:
        addr=socket.gethostbyname(self.uri.upper())
        l=ldap.initialize(f"""
          ldap://{addr}
        """)
        l.protocol_version=ldap.VERSION3
        l.set_option(ldap.OPT_REFERRALS,self.prt)
        l.simple_bind_s(username,self.ps)
        return True
      except ldap.INVALID_CREDENTIALS:
        return False
      except Exception:
         return False