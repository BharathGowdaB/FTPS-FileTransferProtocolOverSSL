import threading
import os,sys,re,traceback
import shutil
import ssl,random
from socket import *

class ftpsServer :
    controlServer = None
    db = {}
    server_cert = None
    server_key = None
    serverName = 'FTPS'
    serverHost = ''
    serverPort = 21
    serverDir = ''
    isServer = False
    lastexpcetion = None
    userfunction = { }
    maxDataConTime = 30
    maxDataSize = 2048
    #Constructor 
    def __init__(self,cert,key,ftpsStorage,serverName='FTPS',serverDirectory=os.getcwd()) :
        #self.server = SSLServerSocket
        self.db = ftpsStorage
        self.serverName = serverName
        self.serverDir = serverDirectory
        self.server_cert = cert
        self.server_key = key

    def traceback(self) :
        print(self.lastexpcetion)

    #RegExp for verifing commands syntax and listing arguments
    cmdPat = re.compile(r'^([\w]{1,4})\s*',re.I)
    userPat = re.compile(r'^(.{1,4}) (\w+)$',re.I)
    passPat = re.compile(r'^(.{1,4}) ([\w@$]{4,10})$',re.I)
    mdirPat = re.compile(r' ([^-][\S]*|-recursive|-[r])',re.I)
    cwdPat = re.compile(r'^cwd\s+([\S]*)\s*$',re.I)
    helpPat = re.compile(r'(help| -[\w]+)',re.I)
    listPat = re.compile(r'^list\s+-(f|d|onlyfiles|onlydirectories)\s*$',re.I)
    storPat = re.compile(r'\s+([\S]+\.[\S]+)',re.I)
    cperFilePat = re.compile(r'[\S]+',re.I)

    #Bind the SSLSocket to IP Address and Port and Start the server
    def bind(self,host='',port=21) :
        self.serverHost = host
        self.serverPort = port
        self.controlServer = self.sslSocket()
        self.controlServer.bind((host,port))
        self.controlServer.listen(5)
        self.isServer = True
        print('FTPS Server Ready')

    #Start Accepting Client request ; //Using multi-threading concepts for multi-user system
    def start(self) :
        while self.isServer :
            try :
                clientSocket,addr = self.controlServer.accept()
                print(clientSocket)
                client = threading.Thread(target=self.clientHandler, args=(clientSocket,addr),daemon=True)
                client.start()
            except :
                #Gives SSLSocket Errors
                print(sys.exc_info())
                type,value,traceback = sys.exc_info()
                print('Error in Accepting Client :',type)

    #Close the Server
    def close(self) :
        self.isServer = False
        self.controlServer.close()

    #Command handler before user login
    def clientHandler(self,client,addr) :
        done = False
        userDetail = {}
        client.send(('223 : Connection established over SSL - '+self.serverName).encode())
        while not done :
            try :
                req = client.recv(1024).decode()
                if(req == '') : continue
                cmd = self.cmdPat.findall(req)[0].upper()
                res = {}
            # USER : (User Name) : checks is requested user if legit or not
                if cmd == 'USER' :  
                    res = self.user(req) 
                    userDetail = res['userDetail']
            # PASS :(Password) : authenticates the requested user, it follows user command
                elif cmd == 'PASS' :
                    res = self.passwd(userDetail,req)
                    if not res['error'] :
                        t = threading.Thread(target=self.controlConnection,args=(userDetail,client,addr),daemon=True)
                        t.start()
                        done = True
            # QUIT :(Quit) Terminate or end the user session      
                elif cmd == 'QUIT' : 
                    res['response'] = '755 : Closing control connection'
                    done = True
                else :
                    res['response'] = "530 LoginError : Not logged in"

                client.send(res['response'].encode())
            except :
                print('Error in clientHandler :',client)
                try :
                    client.send('755 : Closing control connection'.encode())
                    client.close()
                except :
                    print('Error in clientHandler :','Connection Terminated',client)
                done = True
                break

    #Command handler for a logged user
    def controlConnection(self,userDetail,client,addr) :
        done = False
        newuser = {}                #store new user if a logged user wants to switch to a different account
        while not done :
            try :
                req = client.recv(1024).decode()
                if(req == '') : continue
                res = {}
                try :
                    cmd = self.cmdPat.findall(req)[0].upper()
                except :
                    client.send('503 SyntaxError :"<cmd> [options]" ; Command not found\n\'cmd\' can be 1 to 4 characters'.encode())
                    continue   
            # PWD : (Path of Working Directory) return user's working directory, this is same as user['home'] field in database
                if cmd == 'PWD' : res['response'] = '200 : '+ userDetail['curPer'] +'  ~/'+(os.path.basename(userDetail['home'])+os.path.sep+userDetail['cwd']).replace(os.path.sep,'/') 
            # LIST :(List files) return a list of files in current directory along with user's permission on them
                elif cmd == 'LIST' : 
                    rlist = self.__list(req,userDetail)
                    ls = []
                    for item in rlist :
                        ls.append(item[0].ljust(20)+'\t-\t'+item[1].ljust(14)+'\t-\t'+item[2])
                    if len(ls) > 0 : res['response'] = '254 : List\n'+'Name'.ljust(20)+'\t \t'+'Permission'.ljust(14)+'\t\t'+'Type\n'+''.ljust(20,'-')+'\t \t'+''.ljust(14,'-')+'\t\t'.ljust(10,'-')+'\n'+'\n'.join(ls)
                    else : res['response'] = '255  : Folder is empty'
            # RETR , STOR : creates new data connection for specified file transfer ,
                # STOR :(Store files) file will be stored in the current directory
                # RETR :(Retrive files) specified files will be retrived and stored in client's pwd(in remote host)
                elif cmd == 'RETR' or cmd == 'STOR':
                    if '/' in req : res['response'] = '580 RefereceError : Use only filenames,\ndon\'t use relative path or directory'
                    else :
                        flist = self.storPat.findall(req)
                        client.send('130 : Data connection established,\ntransfering requested data'.encode())
                        path = os.path.join(userDetail['home'],userDetail['cwd'])
                        pwalk = self.pathWalk(path)
                        for f in flist :
                            print(f)
                            r =  self.__file(cmd,f,path, pwalk,userDetail)
                            client.send(r.encode())
                        client.send('END : Data transfer successful'.encode())
                        continue
            # CWD :(Current working directory) returns path to directory the user's in
                elif cmd == 'CWD' : res['response'] = self.chdir(req,userDetail)
            # MDIR , RDIR : create or remove a directory,user has to have 'w'(write) permission in cwd
                # MDIR :(Make Directory) Create one or more  directories ,has '-r' option for recursive creation of directories
                # RDIR :(Remove Directory) Remove one or more  directories ,
                #  has '-r' option for recursive deleting directories as per current user's permissions
                elif cmd == 'MDIR' or cmd == 'RDIR' :
                    if not re.compile('^....\s+([\S]+)').search(req) : res['response'] = '531 SyntaxError : Required arguments not passed'
                    else : res['response'] = '200 : Command ok\n' +self.__dir(req,userDetail) 
            # PPER :(Present Permission of file/Dir) Returns permission at different level of designation defined in database['perm_hier']   
                elif cmd == 'PPER' :
                    args = self.cperFilePat.findall(req)        #stor arguments as a list
                    args.pop(0)                                 #remove the cmd from the list
                    path = os.path.join(self.serverDir,os.path.join(userDetail['home'],userDetail['cwd']))
                    pwalk = os.path.join(userDetail['home'],userDetail['cwd'])
                    plist = pwalk.split('\\')
                    if plist[0] == '' : plist.pop(0)
                   
                    pwalk = self.db['dir_hier'][plist.pop(0)]
                    per = pwalk['permission']
                    for p in plist :
                        try :
                            pwalk = pwalk['list'][p]
                            if pwalk['mode'] == 'private' :
                                per = pwalk['permission']
                        except :
                            break
                    r = ''
                    if args == [] : 
                        for k,v in self.db['perm_hier'].items() :
                            r += '\n' + k.ljust(15) + '\t' + per.get(v,'---')
                        res['response'] = '322 : '+' ~/'+path.replace(os.path.sep,'/')+'\n\n'+ os.path.basename(path.strip(os.path.sep)) +' : '+ pwalk.get('mode','public')+'\n'+ ''.ljust(20,'-') + r

                    else :
                        nofile = []
                        for f in args : 
                            if os.path.exists(os.path.join(path,f)) :
                                per2 = per
                                w = {}
                                try :
                                    w = pwalk['list'][f]
                                    if w['mode'] == 'private' :
                                        per2 = w.get('permission',per)
                                except :
                                    per2 = per
                                r += '\n\n' +f + ' : '+ w.get('mode','public') + '\n' +''.ljust(20,'-')
                                for k,v in self.db['perm_hier'].items() :
                                    r += '\n' + k.ljust(15) + '\t' + per2.get(v,'---')
                               
                            else :
                                nofile.append(f)
                        if nofile != [] : r += '\nExcluding ' + ' '.join(nofile) + ', file not exist\'s'
                        res['response'] = '320 : ~/'+path.replace(os.path.sep,'/') + r 
            # CPER :(Change Permission of file/Dir) sets mode(public or private) and permission at different level of designation  of a file
                #   a user can only change add permission that he has and only for designation which is below his         
                elif cmd == 'CPER' :
                    args = self.cperFilePat.findall(req)
                    if len(args) > 1 : args.pop(0)
                    else : 
                        client.send('530 SyntaxError : "CPER [dir/filenames] -<pri[vate] | pub[lic]> : <designation> -<permission>.."'.encode())
                        continue
                    files = []
                    nofile = []
                    path = os.path.join(self.serverDir,os.path.join(userDetail['home'],userDetail['cwd']))
                    l = len(args)
                    for i in range(l) :
                        if args[0].startswith('-') :
                            break
                        else :
                            f = args.pop(0)
                            if os.path.exists(os.path.join(path,f)) :
                                files.append(f)
                            else :
                                nofile.append(f)
   
                    typ = args.pop(0)
                    if '-pri' in typ.lower() : 
                        if args == [] : res['response'] =  self.__cper(userDetail,files,'pri',args)
                        elif ':' == args[0] : 
                            args.pop(0)
                            res['response'] =  self.__cper(userDetail,files,'pri',args)
                    else :
                        res['response'] = self.__cper(userDetail,files,'pub')
                            
                    if nofile != [] :
                        res['response'] += '\n ; Excluding for : '+' '.join(nofile)+' , No such file exist\'s'
            # USER : (User Name) : checks is requested new user if legit or not
                elif(cmd == 'USER') :
                    res = self.user(req)
                    newuser = res['userDetail']
            # PASS :(Password) : authenticates the requested user, it follows user command
                elif(cmd == 'PASS') :
                    res = self.passwd(newuser,req)
                    if not res['error'] :
                        t = threading.Thread(target=self.controlConnection,args=(newuser,client,addr),daemon=True)
                        t.start()
                        done = True
            # QUIT :(Quit) Terminate or end the user session   
                elif cmd == 'QUIT' :
                    res['response'] = '755 : Closing control connection'
                    #client.close()
                    done = True
            # Check for any other functions available to response for a command
                # these function are externally defined to add more functionallity
                else :
                    try :
                        res['response'] = self.userfunction[cmd](req)
                    except : 
                        res['response'] = '502 : Command not implemented'
                # Send response to the client for the given input
                client.send(res['response'].encode())
            except :
                print('Closing client')
                self.lastexpcetion = traceback.print_exc()
                print(sys.exc_info())
                try :
                    client.send('754 : Connection Lost'.encode())  
                    client.close()  
                except :
                    print('No Client')
                done = True
                break
    
    #cper (change permission of a file) : sets mode(public or private) and permission at different level of designation  of a file
    #       a user can only change add permission that he has and only for designation which is below his 
    def __cper(self,user,files,typ,args=[]) :
        if user['cwd'] == '' : path = user['home']
        else : path = os.path.join(user['home'],user['cwd'])
        plist = path.split(os.path.sep)
        if plist[0] == '' : plist.pop(0)
        if 'pri' in typ : typ = 'private'
        elif 'pub' in typ : typ = 'public'
        
        start = plist.pop(0)
        isPartial = []
        self.db['dir_hier'][start] = self.__dirHier(self.db['dir_hier'][start],plist,user,typ,args,files,{"1" : "RWX","2" : "RWX", self.db['perm_hier'].get('viewers') :"R--"},isPartial)

        if isPartial != [] :
            r = ''
            for i in isPartial :
                if i != True :
                    r += '\n' + i
            return '321 : Permissions changed as permitted'+r
        return '320 : Permissions changed successfully'

    #dirHier : (Directory Hierarchy) 
    # db : database containing directory hierarchy, plist : directory path, user : current user-info, typ : new file mode (public or private)
    # args : new permission at designations, flist : filename list whose permissions to be changed, lastPer : last private directory permission 
    # isPartial : list containing response messages
    def __dirHier(self,db,plist,user,typ,args,flist,lastPer,isPartial) :
        if len(plist) > 0 :
            file = plist.pop(0)
            if not db.get('mode',None) : db['mode'] = 'public'
            if not db.get('list',None) : db['list'] = {}

            if db['mode'] == 'private' :
                lastPer = db.get('permission',lastPer)
            db['list'][file] = self.__dirHier(db['list'].get(file,{}),plist,user,typ,args,flist,lastPer,isPartial)
            return db

        if len(plist) <= 0 :
            newPer = {}
            phier = self.db['perm_hier']
            utyp = []
            userPer = db.get('permission',lastPer).get(user['dest'],'---')
            for i in args :
                pat = userPer.lower()
                per = re.compile('^-([R-][W-][X-])$',re.I).findall(i)
                if per != [] : 
                    if pat.lower() != per[0].lower() : isPartial.append(True)
                    p = ''
                    p += per[0][0] if 'r' in pat else  '-'
                    p += per[0][1] if 'w' in pat else  '-'
                    p += per[0][2] if 'x' in pat else  '-'
                    for j in range(len(utyp)) :
                        newPer[utyp.pop(0)] = p
                else :
                    order = phier.get(i,'999')
                    if order != '999' and int(user['dest']) < int(order):
                        utyp.append(order)
                    else : isPartial.append(True)

            if len(flist) == 0 :
                if not 'rw' in userPer.lower() : 
                    isPartial.append('542 AccessError : Read-Write permission required')
                    return db
                db['mode'] = typ
                if typ == 'private' :
                    if not db.get('permission',None) : db['permission'] = lastPer
                    for p,v in newPer.items():
                        db['permission'][p] = v.upper()
            else :
                if not db.get('mode',None) : db['mode'] = 'public'
                if not db.get('list',None) : db['list'] = {} 
                if db['mode'] == 'private' :
                    lastPer = db.get('permission',lastPer)
                for f in flist :
                    lastPer = db.get('permission',lastPer)
                    db['list'][f] = self.__dirHier(db['list'].get(f,{}),[],user,typ,args,[],lastPer,isPartial)              
        return db    

    # Traverse through directory hierarchy
    def pathWalk(self,path) :
        pwalk = {}
        path = path.strip(os.path.sep)
        path = path.strip(' ./')
        try :
            plist = list(path.split(os.path.sep))
            if plist[0] == '' : plist.pop(0)
            pwalk = self.db["dir_hier"][plist.pop(0)] 
            for d in plist :
                try :
                    pwalk = pwalk['list'][d]
                except :
                    pwalk = {}
                    break
        except :
            print('Error in pathWalk ',sys.exc_info())
        return pwalk

    # Function to handle directory related opertions : create directories , remove directories
    def __dir(self,cmd,user) :
        c = self.cmdPat.findall(cmd)[0].upper()
        args = ''
        pwalk = self.pathWalk(user['home'])

        for path in self.mdirPat.findall(cmd) :
            path = path.strip()
            if path.upper().startswith('-R') : 
                args += 'r'
                break

        if c == 'MDIR' :
            r = []
            for path in self.mdirPat.findall(cmd) : 
                if '../' in path : r.append(path+' - 552 PathError : Usage of "../" not Supported')
                elif path.startswith('-') : continue
                else : 
                    r.append(path)
                    path.strip(' ./')
                    if path == '' : 
                        r[len(r)-1] += ' - 571 DirError : Not a valid name'
                        continue
                    curPer = user['curPer']
                    path = path.replace('/',os.path.sep)
                    plist = path.split(os.path.sep)
                    if plist[0] == '' : plist.pop(0)
                    for p in plist:
                        try :
                            pwalk = pwalk['list'][p]
                            if(pwalk['mode'] == 'private') :
                                try :
                                    curPer = pwalk['permission'].get(user['dest'],'---')
                                except :
                                    curPer = '---'
                        except :
                            continue
    
                    newPath = os.path.join(user['cwd'],path)
                    if 'w' not in curPer.lower() : 
                        r[len(r)-1] += ' - 540 AccessError : Write permission required'
                        continue
                    newPath = os.path.join(self.serverDir,os.path.join(user['home'],newPath))
                    if  os.path.exists(newPath) : r[len(r)-1] +=  ' - 551 PathError : Path already exists'
                    elif 'r' in args : 
                        os.makedirs(newPath)
                        r[len(r)-1] +=  ' - 260 : Directory created sucessfully'
                    elif not os.path.exists(os.path.dirname(newPath)) : r[len(r)-1] += " - 550 PathError : Path doesn\'t exists"
                    else : 
                        os.mkdir(newPath)   
                        r[len(r)-1] +=  ' - 260 : Directory created sucessfully'
            return '\n'.join(r)
 
        elif c == 'RDIR' :
            r = []
            for path in self.mdirPat.findall(cmd) :  
                if '../' in path :  r.append(path+' - 552 PathError : Usage of "../" not Supported')
                elif path.startswith('-') : continue
                else : 
                    r.append(path)
                    path = path.strip(' .')
                    if path == '/' :  newPath = os.path.join(user['home'],user['cwd'])
                    else :
                        path = path.strip('/')
                        path = path.replace('/',os.path.sep)
                        newPath = os.path.join(user['home'],user['cwd'],path)

                    if not os.path.exists(os.path.join(self.serverDir,newPath)) : r[len(r)-1] += " - 550 PathError : Path doesn\'t exists"
                    elif 'r' in args : 
                        partial = False
                        pwalk = self.pathWalk(newPath)
                        lastPer = user['curPer']
                        try :
                            if pwalk['mode'] == 'private' :
                                lastPer = pwalk.get('permission',{}).get(user['dest'],'---')
                        except :
                            print(456,sys.exc_info())
                
                        partial = self.__delRecrDir(pwalk,user,newPath,lastPer)
                        if path == '/' and user['cwd'] == '' :
                            r[len(r)-1] += ' - 262 : Home directory emptyed'
                        else :
                            try  :
                                if os.path.isfile(os.path.join(self.serverDir,newPath)) : os.remove(os.path.join(self.serverDir,newPath))
                                else :  os.rmdir(os.path.join(self.serverDir,newPath))
                            except :
                                print(466,sys.exc_info())
                            if partial : r[len(r)-1] += ' - 264 : Directory removed as Permitted'
                            else : r[len(r)-1] += ' - 263 :  Directory removed sucessfully'
                    else :
                        if path == '/' and user['cwd'] == '' : return '402 Access Denied'
                        curPer = user['curPer']
                        plist = path.split(os.path.sep)
                        if plist[0] == '' : plist.pop(0)
                        for p in plist:
                            try :
                                pwalk = pwalk['list'][p]
                                if(pwalk['mode'] == 'private') :
                                    try :
                                        curPer = pwalk['permission'].get(user['dest'],'---')
                                    except :
                                        curPer = '---'
                            except :
                                continue
                        print(curPer)
                        if 'w' not in curPer.lower() : 
                            r[len(r)-1] += ' - 540 AccessError : Write permission required'
                            continue
                        newPath = os.path.join(self.serverDir,newPath)
                        try :     
                            os.rmdir(newPath)
                        except :
                            r[len(r)-1] += ' - 572 DirError : Directory not empty'
                    if path == '/' : self.chdir('cwd ../',user)
            return '\n'.join(r)

    # (Resursive Directory Deletion) removes directory for which user has Read-Write Permission
    def __delRecrDir(self,pwalk,user,path,lastPer) :
        partial = False
        if os.path.isfile(os.path.join(self.serverDir,path)) :
            try :
                if pwalk['mode'] == 'private' :
                    lastPer = pwalk['permission'].get(user['dest'],'---')
            except :
                print(495,sys.exc_info())

            if 'w' in lastPer.lower() : 
                os.remove(os.path.join(self.serverDir,path))
                return False
            return True
        flist = os.listdir(os.path.join(self.serverDir,path))
    
        for f in flist :
            try :
                twalk = pwalk['list'][f]
                
                if twalk['mode'] == 'private' :
                    try :
                        lastPer = twalk['permission'].get(user['dest'],'---')
                        if 'w' in lastPer.lower() : 
                            partial = partial or self.__delRecrDir(twalk,user,os.path.join(path,f),lastPer)
                            try :
                                os.rmdir(os.path.join(self.serverDir,os.path.join(path,f)))
                            except :
                                print('Error in Recursive Directory Deletion',sys.exc_info())
                        else : partial = True
                    except :
                        partial = True
                        continue
                else :
                    if 'w' in lastPer.lower() :
                        partial = partial or self.__delRecrDir(twalk,user,os.path.join(path,f),lastPer)
                        try :
                            os.rmdir(os.path.join(self.serverDir,os.path.join(path,f)))
                        except :
                            print('Error in Recursive Directory Deletion',sys.exc_info())
            except :
                if 'w' in lastPer.lower() :
                    try :
                        shutil.rmtree(os.path.join(self.serverDir,os.path.join(path,f)) )
                    except :
                        os.remove(os.path.join(self.serverDir,os.path.join(path,f)))
                continue
        return partial
    
    # user : retrives user info from database['users']
    def user(self,cmd) :
        res = {'response' : '' ,'userDetail' : {} }
        arg = self.userPat.search(cmd)
        if arg : 
            user = arg.group(2)
            res['userDetail'] = self.db['users'].get(user,{})
            if res['userDetail'] == {} : res['response'] = '531 No User'
            else : 
                res['response'] = '331 : Username OK, need password'
                res['userDetail']['name'] = user
                res['userDetail']['cwd'] = ''
                res['userDetail']['dest'] = self.db['perm_hier'][res['userDetail'].get('designation',"viewer")]

                path = res['userDetail']['home']
                path = path.strip(' ./')
                path = path.replace('/','\\')
                pwalk = self.pathWalk(path)
                per = 'RWX'
                try :
                    if pwalk['mode'] == 'private' :
                        try :
                            per = pwalk['permission'].get(res['userDetail']['dest'],'---')
                        except :
                            per = '---'
                except :
                    per = 'RWX'
                res['userDetail']['homePer'] = per
                res['userDetail']['curPer'] = per
        else : res['response'] = '530 SyntaxError : "USER <username>" \ni) \'username\' must be a single word consisting of alphabets, digits and underscore.'
        return res

    # passwd :(Password) Authenticates the user
    def passwd(self,user,cmd) :
        res = {'response' : '' ,'error':True}
        if not user.get('name',None) : 
            res['response'] = '532 UserError : Set User'
            return res

        user['pwd'] = user['home']
        arg = self.passPat.search(cmd)
        if arg : 
            password = arg.group(2)
            if user['password'] == password : 
                res['response'] = '332 Password OK\n'+user['name']+' Logged Successfully. '
                res['error'] = False
            else : res['response'] = '531 : Password INCORRECT'
        else : res['response'] = '530 SyntaxError : "PASS <password>" \ni)\'password\' must be a single word consisting of alphabets, digits and special character(_@$)'
        
        return res

    # chdir : (change directory) and get user premission of the changed directory
    def chdir(self,cmd,user) :
        arg = re.compile(r'^cwd\s+([\S]*)\s*$',re.I).findall(cmd)[0]
        arg = arg.strip(' /')
        flist = arg.split('/')
        print(268,flist)
        newCWD = user['cwd']
        newCWD = newCWD.strip(' /')

        for folder in flist :
            if ' ' in folder or folder == '': continue
            if folder == '.' : continue
            elif folder == '..' :
                if newCWD == '' : return '543 AccessError : Access denied '
                else : newCWD = os.path.dirname(newCWD)
            else :
                newCWD = os.path.join(newCWD,folder)

        #print(313,newCWD)
        #print(313,os.path.join(self.serverDir,os.path.join(os.path.join(user['home']),newCWD)))
        if not os.path.exists(os.path.join(self.serverDir,os.path.join(os.path.join(user['home']),newCWD))) : return '404 Path doesn\'t exists'

        if not os.path.isdir(os.path.join(self.serverDir,os.path.join(user['home'],newCWD))) : newCWD = os.path.dirname(newCWD)
        #print(313,newCWD)
        dlist = list(newCWD.split(os.path.sep))
        if dlist[0] == '' : dlist.pop(0)
        
        pwalk = self.pathWalk(user['home'])
        #curdir = ''
        curPer = user['homePer']
        walkCWD = ''
        walk = True
        #print(301,'\t',pwalk)
        for d in dlist :
            try :
                pwalk = pwalk['list'][d]
                #print(93,walkCWD)
                if pwalk['mode'] == "private" :
                    try :
                        per = pwalk['permission'].get(user['dest'],'---')
                        if per != '---' :
                            curPer = per.upper()
                            #curdir = ['private',per[user['name']]]
                            walkCWD = os.path.join(walkCWD,d)   
                        else :
                            walk = False
                            break     
                    except :
                        walk = False
                        break 
                else :
                    walkCWD = os.path.join(walkCWD,d)        
            except :
                walkCWD = os.path.join(walkCWD,d)
        
        user['curPer'] = curPer
        if walk :  
            user['cwd'] = newCWD
            return '241 : Directory changed sucessfully'
        elif walkCWD == user['cwd'] : return '405 Access Denied'
        else :
            user['cwd'] = walkCWD 
            return '242 : Directory changed based on users\'s permission'

    # list all file whic is accessible by user in current directory
    def __list(self,cmd,user) :
        args = self.listPat.findall(cmd)
        if args == [] : args = None
        else : args = args[0]

        if user['cwd'] == '' : path = user['home']
        else :  path =  os.path.join(user['home'],user['cwd'])

        flist = os.listdir(os.path.join(self.serverDir,path))
        pwalk = self.pathWalk(os.path.join(user['home'],user['cwd']))

        rlist = [] 
        tlist = []
        for file in flist :
            try :
                if pwalk['list'][file]['mode'] == 'private' :
                    try :
                        per = pwalk['list'][file]['permission'].get(user['dest'],'---')
                        if 'r' in per.lower() : tlist.append([file,per])
                    except :
                        print(673,sys.exc_info())
                else :
                    tlist.append([file,user['curPer']])
            except :
                tlist.append([file,user['curPer']])

        for item in tlist :
            if os.path.isfile(os.path.join(os.path.join(self.serverDir,path),item[0])): item.append('<file>')
            else : item.append('<dir>')

        if args == None : rlist = tlist
        elif 'f' in args : 
            for file in tlist :
                if file[2] == '<file>' : rlist.append(file)            
        elif 'd' in args :
            for file in tlist :
                if file[2] == '<dir>' : rlist.append(file)      
        
        return rlist

    # Function to handle file transfer over data connection
    def __file(self,cmd,file,path,pwalk,user) :
        fpath = os.path.join(self.serverDir,os.path.join(path,file))
        port = -1
        dataServer = self.sslSocket()
        curPer = user['curPer']
        try :
            pwalk = pwalk['list'][file]
            if pwalk['mode'] == 'private' :
                curPer = pwalk.get('permission',{}).get(user['dest'],'---')     
        except :
            print(709,sys.exc_info())

        if cmd == 'RETR' :
            if 'r' not in curPer.lower() : 
                return '541 AccessError : Read permission required'
            if os.path.isfile(fpath) :
                buf = ''
                try :
                    f = open(fpath,'r')
                    buf = f.read()
                    f.close()
                except :
                    print(721,'\t',sys.print_exc())
                    return '580 FileError : Requested file not found'

                while port == -1 :
                    port = random.randint(1025,65000)
                    try :
                        dataServer.bind(('',port))
                        dataServer.listen(8)
                    except :
                        port = -1
                send = threading.Thread(target= self.sendData , args=(dataServer,buf),daemon=True)
                send.start()
            else :
                return '581 FileError : Requested file doesn\'t exists'
            
            return 'CONT : '+str(port)+' '+file
        
        elif cmd == 'STOR' :
            if 'w' not in curPer.lower() : 
                return '540 AccessError : Write permission required'
            while port == -1 :
                port = random.randint(1025,65000)
                try :
                    dataServer.bind(('',port))
                    dataServer.listen(8)
                except :
                    port = -1
            send = threading.Thread(target= self.recvData , args=(dataServer,fpath),daemon=True)
            send.start()
            return 'TNOC : '+str(port)+' '+file
    
    # used to kill a data transfer
    def killServer(self,server,buf) :
        server.close()
        return
    
    # (Receive Data from a user) used to store a file send by the user, maxConnectionTime = 30sec
    def recvData(self,server,fpath) :
        isClient = False
        timer = threading.Timer(self.maxDataConTime,self.killServer,args=(server,fpath))
        timer.start()
        try :
            buf = ''
            client,addr = server.accept()
            client.send('131 : File transfer started '.encode())
            client.send('TNOC : transfering..'.encode())
            buf = client.recv(self.maxDataSize).decode()
            print(551, buf ,'\n\n')
            if buf != '' :
                try :
                    f = open(fpath,'w')
                    f.write(buf)
                    f.close()
                except :
                    print(774,sys.exc_info())
            client.send('132 : File transfer ended '.encode()) 
            client.send('END : Transfer complete'.encode())
            isClient = True
            client.close()
        except :
            print(780,sys.exc_info())
            isClient = False
        try :
            server.close()
        except :
            print(785,sys.exc_info())
        
        print('closing server')
        return isClient

    # (Transfer Data to a user) used to send a file to requested user, maxConnectionTime = 30sec
    def sendData(self,server,buf) :
        isClient = False
        timer = threading.Timer(30,self.killServer,args=(server,buf))
        timer.start()
        try :
            client,addr = server.accept()
            client.send('131 : File transfer started '.encode())
            client.send('CONT : transfering..'.encode())
            client.send(buf.encode())
            client.send('132 : File transfer ended '.encode())  
            client.send('END : Transfer complete'.encode()) 
            isClient = True
            client.close()
        except :
            print(806,sys.exc_info())
            isClient = False
        try :
            server.close()
        except :
            print(811,sys.exc_info())
        
        print('closing server')
        return isClient
  
    # Create a sslsocket for server
    def sslSocket(self) :
        #-----Creating server
        serverSocket = socket(AF_INET,SOCK_STREAM)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=self.server_cert, keyfile=self.server_key)
        #context.load_verify_locations(cafile=client_certs)
        context.verify_mode = ssl.CERT_NONE
        server = context.wrap_socket(serverSocket,server_side=True)
        return server

class ftpsClient :
    server_cert = None
    serverName = 'FTPS'
    client = None
    cwd = serverName
    maxDataSize = 2048
    user = ''
    # Constructor
    def __init__(self,cert,serverName='FTPS') :
        self.server_cert = cert
        self.client = self.sslSocket()
        self.serverName = serverName
    
    #RegExps for Command syntax checking
    cmdPat = re.compile(r'^(.{1,4})\s*',re.I)
    onlyCmdPat = re.compile(r'([\S]{1,4}$)',re.I)
    userPat = re.compile(r'^(.{1,4}) (\w+)\s*$',re.I)
    passPat = re.compile(r'^(.{1,4}) ([\w@$]{4,10})$',re.I)
    mdirPat = re.compile(r' ([^-][\S]*)',re.I)
    helpPat = re.compile(r'(help| -[\w]+)',re.I)
    retrPat = re.compile(r'\s+([^/\s]+)',re.I)
    cwdPat = re.compile(r'^cwd\s+([\S]+)\s*$',re.I)
    cperPat = re.compile(r'^cper\s*.*\s+-(pub|public|pri|private)\s*',re.I)
    
    # Connect to address = (host,port)
    def connect(self,host='',port=21) :
        self.client.connect((host,port))
        self.response()

    # start the client
    def start(self) :
        cmd = ''
        while cmd == '' :
            cmd = input('[ '+self.cwd +' ]$ ')
        request = threading.Thread(target=self.sendcmd,args=(cmd,))
        request.start()

    # Send a single command over control connection
    def sendcmd(self,cmd) :
        iscmd = False
        cmd = cmd.strip()
        c = self.cmdPat.findall(cmd)[0].upper() 
        if c == 'USER' :
            if self.userPat.search(cmd) : 
                iscmd = True
                self.user = self.userPat.findall(cmd)[0][1]
            else : print('syntax error : "USER <username>" ;username contains alphabets, digits and underscore.')
        elif c == 'PASS' :
            if self.passPat.search(cmd) : iscmd = True
            else : print('syntax error : "PASS <password>" ;password contains alphabets, digits and (_$@)')
        elif c == 'MDIR' or c == 'RDIR' :
            if self.mdirPat.search(cmd) : iscmd = True
            else : print('syntax error : "'+c+' [-options] <directory/s>"')
        elif c == 'RETR' or c == 'STOR' :
            if self.retrPat.search(cmd) : iscmd = True
            else : print('synatx error : "'+c+' <fileName/s>"')
        elif c == 'CWD' :
            if self.cwdPat.search(cmd) : iscmd = True
            else : print('synatx error : "CWD <path>"')
        elif c == 'HELP' :
            if self.helpPat.search(cmd) : iscmd = True
            else : print('syntax error : "HELP [-CMD]"')
        elif c == 'CPER' :
            if self.cperPat.search(cmd) : iscmd = True
            else : print('syntax error : "CPER [dir/filenames] -<pri[vate] | pub[lic]> : <designation> -<permission>.." \n1) for -pub[lic] option <destignation> <permission>.. not required.\n2) designation should match that of database\n3) permission must be of the form \'---\' ex: RWX. RW-')
        elif c in ['QUIT','PWD','LIST'] :
            if self.onlyCmdPat.search(cmd) : iscmd = True
            else : print('syntax error : "'+c+'" ;command doesn\'t require arguments')
        else :
            iscmd = True

        if iscmd :
            try :
                self.client.send(cmd.encode())
                self.response()
            except: 
                print('connection lost')
                return
        nextRequest = threading.Thread(target=self.start,args=())
        nextRequest.start()
    
    # Print responses from server for client commands
    def response(self) :
        res = self.client.recv().decode()
        if res.startswith('332') :
            print('[ '+self.cwd +' ]$ '+res)
            self.cwd = self.user
        elif(res.startswith('75')) :
            print('[ '+self.cwd +' ]$ '+'FTPS connection terminated')
            self.client.close()
            self.endConnection()
        elif res.startswith('13') :
            print('[ '+self.cwd +' ]$ '+res)
            dataHandler = threading.Thread(target=self.dataContHandler,args=())
            dataHandler.start()
        else:
            print('[ '+self.cwd +' ]$ '+res)
            
    # Data connection handler for storing and retrieving file
    def dataContHandler(self) :
        res = self.client.recv(self.maxDataSize).decode()
        if res.startswith('CONT') :
            arg = re.compile(r'^CONT : ([\d]+)\s+([\S]+\.[\S]+)$',re.I).findall(res)[0]
            port = arg[0]
            filename = arg[1]
            data = threading.Thread(target=self.sendRecvData,args=(port,filename))
            data.start()
            print('Trying to establish connection for transfer')
        elif res.startswith('TNOC') :
            arg = re.compile(r'^TNOC : ([\d]+)\s+([\S]+\.[\S]+)$',re.I).findall(res)[0]
            port = arg[0]
            filename = arg[1]
            data = threading.Thread(target=self.sendRecvData,args=(port,filename))
            data.start()
            print('Trying to establish connection for transfer')
        elif res.startswith('END') :
            return
        else :
            print(res)
        dataHandler = threading.Thread(target=self.dataContHandler,args=())
        dataHandler.start()

    # Send-Recv data from the server
    def sendRecvData(self,port,filename) :
        clientData = self.sslSocket()
        try :
            clientData.connect(('localhost',int(port)))
        except : 
            print(157,sys.exc_info())
        
        res = clientData.recv(self.maxDataSize).decode()

        while not res.startswith('END') :
            if res.startswith('CONT') :
                buf = clientData.recv(self.maxDataSize).decode()
                f = open(filename,'w')  
                f.write(buf)
                f.close()
            elif res.startswith('TNOC') :
                f = open(filename,'r') 
                buf = f.read()
                f.close()
                clientData.send(buf.encode())
            else :
                print('[ '+self.cwd +' ]$ '+res)
            
            res = clientData.recv(self.maxDataSize).decode()
        try :
            clientData.close()
        except :
            print(137,sys.exc_info())
        print('[ '+self.cwd +' ]$ ')
    # Close the client
    def endConnection(self) :
        os._exit(0)

    # Function to create sslSocket for control or data connection
    def sslSocket(self) :
        clientSocket = socket(AF_INET,SOCK_STREAM)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cafile=self.server_cert)
        client = context.wrap_socket(clientSocket,server_hostname=self.serverName)
        return client

