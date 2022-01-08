from socket import *

serverName = 'FTPS'
serverControlPort = 21

client = socket(AF_INET,SOCK_STREAM)

client.connect(('localhost',serverControlPort))

client.send('USER user'.encode())
print(client.recv(1024).decode())