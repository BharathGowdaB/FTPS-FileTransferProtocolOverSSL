from socket import *

serverName = 'FTPS'
serverControlPort = 21

serverSocket = socket(AF_INET,SOCK_STREAM)

serverSocket.bind(('',serverControlPort))
serverSocket.listen(5)

print('Server ready')

client,addr = serverSocket.accept()


print(client.recv(1024).decode())
client.send('331 Username OK'.encode())
