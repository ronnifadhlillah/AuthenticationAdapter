import adapter
import ldap
import imaplib
import os
import socket
import tldextract
import sys
import re

class Strategy:
    def IMAP(self,uri,un,ps,prt):
        if Strategy.DomainValidate(un,uri,prt) is False:
            return False
        dc=uri.split('.')
        if tldextract.extract(uri).subdomain is not '':
            username='%s@%s'%(un,'.'.join(dc[1:]))
        try:
            imp=imaplib.IMAP4_SSL(uri,port=prt)
            imp.login(username,ps)
            return True
        except imaplib.IMAP4.error:
            return False
        imp.close()

    def SMBAD(self,uri,un,ps,prt):
        # DomainValidate(un,uri)
        # Validation if using subdomain
        if Strategy.DomainValidate(un,uri,prt) is False:
            return False
        # Depending of Server NetBIOS Name
        dc=uri.split('.')
        if tldextract.extract(uri).subdomain is not '':
            username='%s@%s' % (un,'.'.join(dc[1:]))
            dn=[]
            for i in dc[1:]:
                dn.append(str(i))
        else:
            username='%s@%s' % (un,'.'.join(dc[0:]))
            dn=[]
            for i in dc[0:]:
                dn.append(str(i))
        # Mastering DN
        bj=',DC='.join(dn)
        base_dn=str('DC='+bj)
        addr=socket.gethostbyname(dc[0].upper())
        # # gak attr=['memberOf'] --> For testing the AD
        l=ldap.initialize('ldap://%s' % addr)
        l.protocol_version=ldap.VERSION3
        l.set_option(ldap.OPT_REFERRALS,389)
        try:
            l.simple_bind_s(username,ps)
        #     # testing ldap connection --> For testing the AD
            # auth=l.search_s(base_dn,ldap.SCOPE_SUBTREE,'(objectClasas=*)',attr) #--> For testing the AD
            # for dn,entry in auth: #--> For testing the AD
            #     print('Processing',repr(entry)) #--> For testing the AD
            # return True
        except ldap.INVALID_CREDENTIALS:
            return False

    def DomainValidate(un,uri,prt):
            # Validation URI parameter
            # uri contain number
            # Validation if input using IP as Domain Controller , it's not recommend
            if uri.replace('.','').isnumeric() == True:
                return False
            # uri contain http://,https://,www.
            pattern=re.match('((http|https)://)(www.)?[a-zA-Z0-9@:%._\\+~#?&//=]{2,256}\\.[a-z]{2,6}\\b([-a-zA-Z0-9@:%._\\+~#?&//=]*)',uri)
            if bool(pattern) == True:
                return False
            # Port validation
            port=[995,993,465,143,389]
            if prt not in port:
                return False
