import adapter

c=adapter.Strategy()
conn=c.SMBAD('smb.domain.tld','username','password',port)

if conn is True:
    print('Login Success')
elif conn is False:
    print('Login Un-successful')
