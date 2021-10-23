# AuthenticationAdapter
#### Auth Strategy by advantage of IMAP User, AD.

Simple authentication for integrating local server / AD user, IMAP account using LDAP Protocol.

Basic usage
```
c=adapter.Strategy('domain.tld','username','password',port)
conn=c.Imap()/c.WinAD()/c.SmbAD()
```

Response sample
```
if conn is True:
    # Response
elif conn is False:
    # Response
```
