from socket import *
import ssl
import os,threading,sys
import re
import ftpsLib

serverName = 'FTPS'
server_cert = 'docs/server/server.crt'

ftps = ftpsLib.ftpsClient(server_cert,serverName=serverName)
ftps.connect(host='localhost',port=21)
ftps.start()

