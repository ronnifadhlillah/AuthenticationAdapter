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
        if (Strategy.DomainValidate(self))==False:
            print('Something wrong with your parameter. Check it out')
            sys.exit()

    def Imap(self):
        if tldextract.extract(self.uri).subdomain is not '':
            username='%s@%s'%(self.un,'.'.join(self.dc[1:]))
        try:
            imp=imaplib.IMAP4_SSL(self.uri,port=self.prt)
            imp.login(username,self.ps)
            return True
        except imaplib.IMAP4.error:
            return False
        imp.close()

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

    def WinAD(self):
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

    def DomainValidate(self):
            # Validation URI parameter
            # uri contain number
            # Validation if input using IP as Domain Controller , it's not recommend
            if self.uri.replace('.','').isnumeric() == True:
                return False
            # uri contain http://,https://,www.
            pattern=re.match('((http|https)://)(www.)?[a-zA-Z0-9@:%._\\+~#?&//=]{2,256}\\.[a-z]{2,6}\\b([-a-zA-Z0-9@:%._\\+~#?&//=]*)',self.uri)
            if bool(pattern) == True:
                return False

    def doAuthentication(self,username,base_dn,dn):
        addr=socket.gethostbyname(self.uri.upper())
        l=ldap.initialize('ldap://%s' % addr)
        l.protocol_version=ldap.VERSION3
        l.set_option(ldap.OPT_REFERRALS,self.prt)
        try:
            l.simple_bind_s(username,self.ps)
            # # LDAP testing below is currently running on linux (smb4DAD only)
            # attr=['Domain'] #--> For testing the AD
            # # # testing ldap connection --> For testing the AD
            # auth=l.search_s(base_dn,ldap.SCOPE_SUBTREE,'(objectClass=*)',attr) #--> For testing the AD
            # for dn,entry in auth: #--> For testing the AD
            #     print('Processing',repr(entry)) #--> For testing the AD
            return True
        except ldap.INVALID_CREDENTIALS:
            return False
