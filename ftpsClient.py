from socket import *
import ssl
import os,re
import threading

serverName = 'FTPS'
controlPort = 8001
dataPort = 20

server_cert = 'docs/server/server.crt'

clientSocket = socket(AF_INET,SOCK_STREAM)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
#context.check_hostname = False
#context.verify_mode = ssl.CERT_NONE
context.load_verify_locations(cafile=server_cert)

client = context.wrap_socket(clientSocket,server_hostname=serverName)

#print(ssl.get_server_certificate(('localhost',8001)))

class ftpsClient :
    def __init__(self,SSLSocket) :
        self.client = SSLSocket
    
    #RegExps for Command syntax checking
    cmdPat = re.compile(r'^(.{1,4})\s*',re.I)
    onlyCmdPat = re.compile(r'([\S]{1,4}$)',re.I)
    userPat = re.compile(r'^(.{1,4}) (\w+)$',re.I)
    passPat = re.compile(r'^(.{1,4}) ([\w@$]{4,10})$',re.I)
    mdirPat = re.compile(r' ([^-][\S]*)',re.I)
    helpPat = re.compile(r'(help| -[\w]+)',re.I)
    retrPat = re.compile(r'^....(\s+[\S]+)?\s+([^/\s]+)$',re.I)
    cwdPat = re.compile(r'^cwd\s+([\S]+)\s*$',re.I)
    
    #Variables for 
    client
    cwd = 'FTPS'

    def connect(self,host='',port=21) :
        self.client.connect((host,port))
        self.response()

    def start(self) :
        cmd = ''
        while cmd == '' :
            cmd = input('[~/'+self.cwd+' ] $')
        #print(threading.active_count(),cmd)
        request = threading.Thread(target=self.sendcmd,args=(cmd,))
        request.start()

    def sendcmd(self,cmd) :
        iscmd = False
        cmd = cmd.strip()
        c = self.cmdPat.findall(cmd)[0].upper() 
        if c == 'USER' :
            if self.userPat.search(cmd) : iscmd = True
            else : print('syntax error : "USER <username>" ;username contains alphabets, digits and underscore.')
        elif c == 'PASS' :
            if self.passPat.search(cmd) : iscmd = True
            else : print('syntax error : "PASS <password>" ;password contains alphabets, digits and (_$@)')
        elif c == 'MDIR' or c == 'RDIR' :
            if self.mdirPat.search(cmd) : iscmd = True
            else : print('syntax error : "'+c+' [-options] <directory/s>"')
        elif c == 'RETR' or c == 'STOR' :
            if self.retrPat.search(cmd) : iscmd = True
            else : print('synatx error : "'+c+' [path] <fileName>"')
        elif c == 'CWD' :
            if self.cwdPat.search(cmd) : iscmd = True
            else : print('synatx error : "CWD <path>"')
        elif c == 'HELP' :
            if self.helpPat.search(cmd) : iscmd = True
            else : print('syntax error : "HELP [-CMD]"')
        elif c in ['QUIT','PWD','LIST','ABOR'] :
            if self.onlyCmdPat.search(cmd) : iscmd = True
            else : print('syntax error : "'+c+'" ;command doesn\'t require arguments')
        else :
            iscmd = True

        if iscmd :
            self.client.send(cmd.encode())
            self.response()
        nextRequest = threading.Thread(target=self.start,args=())
        nextRequest.start()
    
    def response(self) :
        res = self.client.recv().decode()
        print('[~/'+self.cwd,'] $'+res)
        if(res.startswith('75')) :
            print('FTPS connection terminated')
            self.client.close()
            self.endConnection()
      
    def endConnection(self) :
        os._exit(0)

done = False
ftps = ftpsClient(client)
ftps.connect(host='localhost',port=8001)
ftps.start()

