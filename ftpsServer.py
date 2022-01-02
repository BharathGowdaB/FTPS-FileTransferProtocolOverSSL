from socket import *
import ssl
import threading
import os,sys,re,traceback
import json
import shutil

#serverName should be same as that in the server_cert
serverName = 'FTPS'
serverControlPort = 8001
serverRunning = True
server_cert = 'docs/server/server.crt'
server_key = 'docs/server/server.key'
database = open('docs/database.json','r')

db = json.load(database)

#client_certs = 'docs/client/client.crt'

#-----Creating server for Control Connections running at port 21
serverSocket = socket(AF_INET,SOCK_STREAM)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=server_cert, keyfile=server_key)
#context.load_verify_locations(cafile=client_certs)
context.verify_mode = ssl.CERT_NONE
server = context.wrap_socket(serverSocket,server_side=True)

#------Server created



#Function to terminate the server
def endServer() :
    global ftpsserver
    while True :
        x = input()  
        if(x.lower() == 'q') :
            print('Terminating server...')
            ftpsserver.close()
            break
        elif(x.lower() == 't') :
            ftpsserver.traceback()

class ftpsServer :
    server
    db
    serverName = 'FTPS-Server'
    serverDir = ''
    isServer = False
    lastexpcetion = None
    userfunction = {
       
    }

    def __init__(self,SSLServerSocket,databaseJSON,serverName='FTPS-Server',serverDirectory=os.getcwd()) :
        self.server = SSLServerSocket
        self.db = databaseJSON
        self.serverName = serverName
        self.serverDir = serverDirectory

    cmdPat = re.compile(r'^([\w]{1,4})\s*',re.I)
    userPat = re.compile(r'^(.{1,4}) (\w+)$',re.I)
    passPat = re.compile(r'^(.{1,4}) ([\w@$]{4,10})$',re.I)
    mdirPat = re.compile(r' ([^-][\S]*|-recursive|-[r])',re.I)
    cwdPat = re.compile(r'^cwd\s+([\S]*)\s*$',re.I)
    helpPat = re.compile(r'(help| -[\w]+)',re.I)

    def traceback(self) :
        print(self.lastexpcetion)

    def bind(self,host='',port=21) :
        self.server.bind((host,port))
        self.server.listen(5)
        self.isServer = True
        print('FTPS Server Ready')

    def start(self) :
        while self.isServer :
            print(self.isServer)
            try :
                clientSocket,addr = self.server.accept()
                print(clientSocket)
                client = threading.Thread(target=self.clientHandler, args=(clientSocket,addr))
                client.start()
            except :
                #Gives SSLSocket Errors
                type,value,traceback = sys.exc_info()
                print(70,value)

    def close(self) :
        self.isServer = False
        self.server.close()

    def clientHandler(self,client,addr) :
        done = False
        userDetail = {}
        client.send(('223 Connection established over SSL: '+self.serverName).encode())
        while not done :
            try :
                req = client.recv(1024).decode()
                if(req == '') : continue
                cmd = self.cmdPat.findall(req)[0].upper()
                res = {}

                if cmd == 'USER' :  
                    res = self.user(req) 
                    userDetail = res['userDetail']
                elif cmd == 'PASS' :
                    res = self.passwd(userDetail,req)
                    if not res['error'] :
                        t = threading.Thread(target=self.controlConnection,args=(userDetail,client,addr))
                        t.start()
                        done = True
                elif cmd == 'QUIT' : 
                    res['response'] = '755 : Closing Connection'
                    #client.close()
                    done = True
                else :
                    res['response'] = "534 UserError : Login Before Using Commands"

                client.send(res['response'].encode())
            except :
                print('Closing client')
                print(sys.exc_info())
                try :
                    client.send('754 : Connection Lost'.encode())
                    client.close()
                except :
                    print('No Client')
                done = True
                break

    def controlConnection(self,userDetail,client,addr) :
        done = False
        newuser = {}
        while not done :
            try :
                req = client.recv(1024).decode()
                if(req == '') : continue

                res = {}
                try :
                    cmd = self.cmdPat.findall(req)[0].upper()
                except :
                    client.send('505 : Command not found'.encode())
                    continue

                if cmd == 'PWD' : 
                    res['response'] = '452 '+os.path.basename(userDetail['home'])+'\\'+userDetail['cwd']
                    print(res['response'])
                elif cmd == 'CWD' :
                    res['response'] = self.chdir(req,userDetail)
                    #print(148,userDetail)
                elif cmd == 'MDIR' or cmd == 'RDIR' :
                    res['response'] = self.__dir(req,userDetail) 
                elif(cmd == 'USER') :
                    res = self.user(req)
                    newuser = res['userDetail']
                elif(cmd == 'PASS') :
                    res = self.passwd(newuser,req)
                    if not res['error'] :
                        t = threading.Thread(target=self.controlConnection,args=(newuser,client,addr))
                        t.start()
                        done = True
                elif cmd == 'QUIT' :
                    res['response'] = '752 : Closing Connection'
                    #client.close()
                    done = True
                else :
                    try :
                        res['response'] = self.userfunction[cmd](req)
                    except : 
                        res['response'] = '505 : Command not found'

                client.send(res['response'].encode())
            except :
                print('Closing client')
                self.lastexpcetion = traceback.print_exc()
                #print(sys.exc_info())
                try :
                    client.send('754 : Connection Lost'.encode())
                    client.close()
                except :
                    print('No Client')
                done = True
                break
    
    def pathDir(self,path) :
        pwalk = {}
        try :
            plist = list(os.path.split(path.strip(' ./')))
            if plist[0] == '' : plist.pop(0)
            pwalk = self.db["dir_hier"][plist.pop(0)]
            for d in plist :
                try :
                    pwalk = pwalk['list'][d]
                except :
                    break
        except :
            print('error in pathDir')
        return pwalk

    def user(self,cmd) :
        res = {'response' : '' ,'userDetail' : {} }
        arg = self.userPat.search(cmd)
        if arg : 
            user = arg.group(2)
            res['userDetail'] = self.db['users'].get(user,{})
            if res['userDetail'] == {} : res['response'] = '531 No User'
            else : 
                res['response'] = '331 Username OK'
                res['userDetail']['name'] = user
                res['userDetail']['cwd'] = ''
                res['userDetail']['dir_path'] = self.pathDir(res['userDetail']['home'])
                res['userDetail']['cur_dir'] = ['public','']
        else : res['response'] = 'syntax error : username must be a single word consisting of alphabets, digits and underscore.'

        return res

    def passwd(self,user,cmd) :
        res = {'response' : '' ,'error':True}

        if not user.get('name',None) : 
            res['response'] = '534 SET USER'
            return res

        user['pwd'] = user['home']
        arg = self.passPat.search(cmd)
        if arg : 
            password = arg.group(2)
            if user['password'] == password : 
                res['response'] = '332 Password OK\n'+user['name']+' Logged Successfully. '
                res['error'] = False
            else : res['response'] = '532 Password INCORRECT'
        else : res['response'] = 'syntax error : password must be a single word consisting of alphabets, digits and special character(_@$)'
        
        return res

    def __dir(self,cmd,user) :
        c = self.cmdPat.findall(cmd)[0].upper()
        args = ''
        
        #if re.compile(r'^....\s*.*/\s*$').search(cmd) : return '403 PathError : path doesn\'t exists'
        if not((user['cur_dir'][0].lower() == 'private' and 'w' in user['cur_dir'][1].lower()) or user['cur_dir'][0].lower() == 'public'):
                print(user['cur_dir'][0])
                return '403 Permission denied'
                
        for path in self.mdirPat.findall(cmd) :
            path = path.strip()
            if path.upper().startswith('-R') : 
                args += 'r'
                break

        if c == 'MDIR' :
            for path in self.mdirPat.findall(cmd) : 
                if '../' in path : return '405 PathError : usage of "../" not Supported'
                elif path.startswith('-') : continue
                else : 
                    path.strip(' ./')
                    if path == '' : return '403 PathError : path doesn\'t exists'
                    print(user['cwd']+'\\'+path)
                    newPath = os.path.join(os.path.join(user['home'],user['cwd']),path)
                    if  os.path.exists(newPath) : return '405 PathError : path already exists'
                    elif 'r' in args : os.makedirs(newPath)
                    elif not os.path.exists(os.path.dirname(newPath)) : return "403 PathError : path doesn\'t exists"
                    else : os.mkdir(newPath)   

            return '321 Directory : created sucessfully'
        
        elif c == 'RDIR' :
            #check directory permission
            for path in self.mdirPat.findall(cmd) :  
                if '../' in path : return '405 PathError : usage of "../" not Supported'
                elif path.startswith('-') : continue
                else : 
                    path = path.strip(' .')
                    if path == '/' :  newPath = os.path.join(user['home'],user['cwd'])
                    else :
                        path = path.strip('/')
                        newPath = os.path.join(user['home'],user['cwd'],path)
                    print(newPath)
                    if path == '/' and user['cwd'] == '' : return '402 Access Denied'
                    if not os.path.exists(newPath) : return '403 PathError : path doesn\'t exists'
                    elif 'r' in args : 
                       # if newPath == user['home'] : return '402 Access Denied'
                        shutil.rmtree(newPath)
                    else :
                        try :     
                            os.rmdir(newPath)
                        except :
                            return '404 DirError : directory not empty'
                    if path == '/' : self.chdir('cwd ../',user)
            return '322 Directory : deleted sucessfully'

    def chdir(self,cmd,user) :
        arg = re.compile(r'^cwd\s+([\S]*)\s*$',re.I).findall(cmd)[0]
        arg = arg.strip(' /')
        flist = arg.split('/')
        print(268,flist)
        newCWD = user['cwd']
        newCWD = newCWD.strip(' /')

       
        #hpath = os.path.split(newCWD)
        #
        #pwalk = self.db['dir_hier']
        
        
        for folder in flist :
            if ' ' in folder or folder == '': continue
            if folder == '.' : continue
            elif folder == '..' :
                if newCWD == '' : return '400 AccessDenied : '
                else : newCWD = os.path.dirname(newCWD)
            else :
                newCWD = os.path.join(newCWD,folder)

        if not os.path.exists(os.path.join(user['home'],newCWD)) : return '404 Path doesn\'t exists'

        if not os.path.isdir(os.path.join(user['home'],newCWD)) : newCWD = os.path.dirname(newCWD)
        print(313,newCWD)
        dlist = list(newCWD.split('\\'))
        if dlist[0] == '' : dlist.pop(0)
        print(dlist)
        pwalk = user['dir_path']
        
        curdir = ''
        walkCWD = ''
        walk = True

        for d in dlist :
            try :
                pwalk = pwalk['list'][d]
                print(93,walkCWD)
                if pwalk['mode'] == "private" :
                    per = pwalk.get('permission',None)
                    if per and per.get(user['name'],None) :
                        curdir = ['private',per[user['name']]]
                        walkCWD = os.path.join(walkCWD,d)   
                    else :
                        walk = False
                        break      
                else :
                    walkCWD = os.path.join(walkCWD,d)        
            except :
                walkCWD = os.path.join(walkCWD,d)

        print(walkCWD)
        
        if walk : 
            if curdir == '' : curdir = ['public' , '']
            user['cwd'] = newCWD
            user['cur_dir'] = curdir
            print(354,user['cwd'])
            print(355,user['cur_dir'])
            return '431 CWD changed sucessfully'
        elif walkCWD == user['cwd'] : return '405 Access Denied'
        else :
            user['cwd'] = walkCWD
            user['cur_dir'] = curdir
            print(354,user['cwd'])
            print(355,user['cur_dir'])
            return '432 cwd changes as permission applied'

            

serverTerminator = threading.Thread(target=endServer, args = ())
serverTerminator.start()

ftpsserver = ftpsServer(server,db)
ftpsserver.bind(host='',port=8001)
ftpsserver.start()
#print(ftpsserver.dir('MDIR  /wwe  dir2/nghg',{'cwd' : 'Organization'}))
#user = {'cwd' : 'Organization\wwe'}
#print(ftpsserver.chdir('cwd /dir2/sub1/temp.txt/wwe',user))
#print(user)
#print(os.path.exists(user['cwd']))
"""
done = 0
while done == 0 :
    try :
        clientSocket,addr = server.accept()
        client = threading.Thread(target=clientHandler, args=(clientSocket,addr))
        client.start()
    except :
        #Gives SSLSocket Errors
        type,value,traceback = sys.exc_info()

"""
    