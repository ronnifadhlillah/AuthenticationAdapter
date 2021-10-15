import adapter

c=adapter.Strategy('domain.tld','username','password',port)
conn=c.Imap()

if conn is True:
    print('Login Success')
elif conn is False:
    print('Login Un-successful')
