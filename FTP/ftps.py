from socket import *
import threading,json,os,re

serverName = 'FTPS'
serverControlPort = 21
dbPath = 'FTP/FTPdatabase.json'

f = open(dbPath,'r')
db = json.loads(f.read())

serverSocket = socket(AF_INET,SOCK_STREAM)

serverSocket.bind(('',serverControlPort))
serverSocket.listen(5)

print('Server ready')

cmdPat = re.compile(r'^([\w]{1,4})\s*',re.I)
userPat = re.compile(r'^(.{1,4}) (\w+)$',re.I)
passPat = re.compile(r'^(.{1,4}) ([\w@$]{4,10})$',re.I)

def clientHandler(client,addr,user) :
    global db
    while True :
        req = client.recv(1024).decode()
        if req == '' :continue
        cmd = cmdPat.findall(req)[0].upper()
        if cmd == 'USER' :
            name = userPat.findall(req)[0][1]
            user = db.get(name,{})
            if user != {} :
                client.send('331 : Username OK'.encode())
            else :
                client.send('531 : No User'.encode())
        elif cmd == 'PASS' :
            password = passPat.findall(req)[0][1]
            if user == {} : client.send('532 : Set user'.encode())
            elif user['password'] == password : 
                client.send('332 : Password Ok'.encode())
            else : client.send('532 : Password Incorrect'.encode())
        elif cmd == 'LIST' :
            client.send('\n'.join(os.listdir()).encode())
        elif cmd == 'QUIT' :
            client.send('755 : Connection Terminated'.encode())
            break
        else :
            client.send('502 : Command not implemented')
  
isServer = True
while isServer :
    try :
        client,addr = serverSocket.accept()
        client.send('220 : Connection established'.encode())
        clientT = threading.Thread(target=clientHandler,args=(client,addr,{}))
        clientT.start()
    except :
        print(sys.exc_info())