from socket import *  
                if not self.isServer : 
                    print('FTPS Server Closed')
                else : 
                    print(sys.exc_info())
                    type,value,traceback = sys.exc_info()
                    print('Error in Accepting Client :',type)
                    if '/' in req : res['response'] = '590 RefereceError : Use only filenames,\ndon\'t use relative path or directory'
                                    r += '\n' + k.ljust(15) + '\t' + per2.get(v[0],'---')
            return '543 AccessError : Access denied'
                            else : r[len(r)-1] += ' - 263 :  Directory removed successfully'
                        if path == '/' and user['cwd'] == '' : return '443 AccessError : Access Denied'
                        #print(curPer)
                            r[len(r)-1] += ' - 263 : Directory removed successfully'
                            try :
                                os.remove(newPath)
                                r[len(r)-1] += ' - 265 : file removed successfully'
                            except:
                                r[len(r)-1] += ' - 572 DirError : Directory not empty'
        elif walkCWD == user['cwd'] : return '443 AccessError : Access Denied '
            print('''\nCommand Syntax : <cmd> [options]

# USER : (User Name) : checks is requested new user if legit or not
	syntax : USER <username>" \ni) \'username\' must be a single word consisting of alphabets, digits and underscore.

# PASS :(Password) : authenticates the requested user, it follows user command
	syntax : PASS <password>" \ni)\'password\' must be a single word consisting of alphabets, digits and special character(_@$)

# QUIT :(Quit) Terminate or end the user session   
	syntax : QUIT
                           
# PWD : (Path of Working Directory) return user's working directory, this is same as user['home'] field in database
	syntax : PWD

# CWD :(Current working directory) returns path to directory the user's in
	syntax : CWD 
       
# LIST :(List files) return a list of files in current directory along with user's permission on them
	syntax : LIST [-(f|d|onlyfiles|onlydirectories)]

# RETR , STOR : creates new data connection for specified file transfer ,
         # STOR :(Store files) file will be stored in the current directory
         # RETR :(Retrive files) specified files will be retrived and stored in client's pwd(in remote host)
		
	syntax : <STOR | RETR> <fileName/s>

# MDIR , RDIR : create or remove a directory,user has to have 'w'(write) permission in cwd
         # MDIR :(Make Directory) Create one or more  directories ,has '-r' option for recursive creation of directories
	 # RDIR :(Remove Directory) Remove one or more  directories , has '-r' option for recursive deleting directories as per current user's permissions
		
	syntax : <MDIR | RDIR> [-options] <directory/s>

# PPER :(Present Permission of file/Dir) Returns permission at different level of designation defined in database['perm_hier']   
	syntax : PPER [dir/filenames]

# CPER :(Change Permission of file/Dir) sets mode(public or private) and permission at different level of designation  of a file a user can only change add permission that he has and only for designation which is below his         
   	syntax : CPER [dir/filenames] -<pri[vate] | pub[lic]> : <designation> -<permission>..         
''')
            iscmd = False