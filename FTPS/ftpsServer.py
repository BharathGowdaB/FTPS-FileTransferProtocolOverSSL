from socket import *
import ssl
import threading,os,sys
import re,traceback,json
import shutil
import ftpsLib 

#serverName should be same as that in the server_cert
serverName = 'FTPS'
serverHost = 'localhost'
serverPort = 21

#Server Certificate and key
server_cert = 'docs/server/server.crt'
server_key = 'docs/server/server.key'
dbPath = 'docs/database.json'


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

db = ftpsLib.ftpsDatabase(dbPath)
serverTerminator = threading.Thread(target=endServer, args = (),daemon=True)
serverTerminator.start()

ftpsserver = ftpsLib.ftpsServer(server_cert,server_key,db,serverDirectory = 'ServerDirectory')
ftpsserver.bind(host=serverHost,port=serverPort)
ftpsserver.start()

    