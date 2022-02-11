# AuthenticationAdapter
#### Auth Strategy by advantage of IMAP User, AD.

Simple authentication using local server / AD user, IMAP account.

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
