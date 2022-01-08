from socket import *
import re

serverName = 'FTPS'
serverControlPort = 21

client = socket(AF_INET,SOCK_STREAM)

client.connect(('localhost',serverControlPort))
print(client.recv(1024).decode())

userPat = re.compile(r'^(.{1,4}) (\w+)$',re.I)
user = 'Anonymous'
newName = ''
isClient = True

while isClient :
    cmd = input('['+user+'] ')
    if cmd.lower().startswith('user') :
        newName = userPat.findall(cmd)[0][1]
    client.send(cmd.encode())
    res = client.recv(1024).decode()
    if res.startswith('75') :
        isClient = False
    elif res.startswith('332') :
        user = newName
    print('['+user+'] '+res)