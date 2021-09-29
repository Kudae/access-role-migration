import requests 
import json
import os
import pathlib
import urllib3
import re
import sys
import time
import ldap
import os.path
from os import path

#remove insecure https warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def askConfig():

    username = input("Username: ")
    password = input("Password: ")
    fromDomain = input("From Domain: ")
    toDomain = input("To Domain: ")
    api_ip = input("IP Address: ")
    api_port = input("API Port: ")
    ad_domain = input("Active Directory Domain: ")
    
    return username, password, fromDomain, toDomain, api_ip, api_port, ad_domain

username, password, fromDomain, toDomain, api_ip, api_port, ad_domain = askConfig()


#global url variable, import local config file
url = f'https://{api_ip}:{api_port}/web_api'


#clear logs on new debug
def redoLogs(domain):
    fileList = [f"{domain}_publish.json",
                "apiLog.txt",
                f"{domain}_add_access_roles.json"]
    try:
        for x in  fileList:
            os.remove(x)
    except Exception as e:
        print(e)
        pass

if len(sys.argv) > 1 and sys.argv[1] == "-d":
    redoLogs(toDomain)


#help menu
if len(sys.argv) > 1 and sys.argv[1] == "-h": 
    print(
        '''
        [ Usage ]

        Run on Linux: ./access-role-migration

        -d = Debug (Log Files are printed in present working directory)
        -h = Help (see below)
        
        [ Description ]

        Export Access Roles between source and target domains. 

        1. Login to each domain. 
        2. Gather Access Roles from source domain. 
        3. Convert JSON payload of source domain. 
        4. Check if user exists in target domain. 
        5. If user exists in target domain, do not add/set access role. 
        6. If user does not exist in target domain, add/set access role. 
        7. Publish each change. 
        8. Logout

        [ Notes & Limitations]

        - Make sure all sessions are published and 
          no lingering sessions exist on each CMA. 

        - Do not edit any access role objects while 
          script is running. 

        - LDAP / access role group with DN configured 
          as "OU" will not be exported.

          Example: 
          "dn" : "OU=Domain Controllers,DC=domain,DC=local"
 
        - Check apiLog.txt for most general useful debugging information. 

        '''
    )
    quit()
else: 
    if len(sys.argv) > 1 and sys.argv[1] == "-d":
        print("\n\n [ Debug Started... ]\n\n")


# sleep function
def sleeptime(timeval): 
    time.sleep(timeval)


#Debug API/HTTP
def api_debug(defname, ac_url, headers, body, result, api_post): 

    apiLog = 'apiLog.txt'

    if len(sys.argv) > 1 and sys.argv[1] == "-d":
        apiBugs = [
        f"\n\n[ {defname} ]\n",
        f"{defname} : URL : {ac_url} \n",
        f"{defname} : Headers : {headers} \n",
        f"{defname} : Body : {body} \n",
        f"{defname} : JSON RESPONSE : \n{result}\n",
        f"{defname} : Status Code: {api_post.status_code}\n",
        ]
        file1 = open(apiLog, "a")
        file1.writelines(apiBugs)
        file1.close()


# API Login
def api_login(domain): 

    defname = f"API : Login : {domain}"
    
    ac_url = f'{url}/login'
    headers = {'Content-Type' : 'application/json'}
    body = {'user' : f'{username}', 
                'password' : f'{password}',
                'domain' : f'{domain}'}
    api_post = requests.post(ac_url, data = json.dumps(body), headers=headers, verify=False)
    result = json.loads(api_post.text)

    sleeptime(1)
    api_debug(defname, ac_url, headers, body, result, api_post)

    return result


# API Logout
def logout(domain, sid): 
    defname = f"API : Logout : {domain} : {sid['sid']} "

    ac_url = f'{url}/logout'
    x = sid["sid"]
    headers = {'Content-Type' : 'application/json',
                'X-chkp-sid' : f'{x}'} 
    body = {}
    api_post = requests.post(ac_url, data=json.dumps(body), headers=headers, verify=False)
    result = api_post.json()

    sleeptime(1)
    api_debug(defname, ac_url, headers, body, result, api_post)


# API Publish
def publish(domain, sid): 

    defname = f"API : Publish : {domain}"

    ac_url = f'{url}/publish'
    x = sid["sid"]
    headers = {'Content-Type' : 'application/json',
                'X-chkp-sid' : f'{x}'} 
    body = {}
    api_post = requests.post(ac_url, data=json.dumps(body), headers=headers, verify=False)
    result = api_post.json() 

    sleeptime(1.5)
    api_debug(defname, ac_url, headers, body, result, api_post)

    if len(sys.argv) > 1 and sys.argv[1] == "-d":
        with open (f'{domain}_publish.json', 'a') as convert_file:
         convert_file.write(json.dumps(result))


# API - Show Acccess Roles
def show_access_roles(domain, sid): 

    defname = f"API : Show Access Roles : {domain}" 

    ac_url = f'{url}/show-access-roles'
    x = sid["sid"]
    headers = {'Content-Type' : 'application/json',
                'X-chkp-sid' : f'{x}'} 
    body = {'details-level' : 'full'}
    
    api_post= requests.post(ac_url, data=json.dumps(body), headers=headers, verify=False)
    result = json.dumps(api_post.json()) #json.dump takes dictionary as input and returns a string as output

    sleeptime(5)
    api_debug(defname, ac_url, headers, body, result, api_post)
    if len(sys.argv) > 1 and sys.argv[1] == "-d":
        with open (f'{domain}_show_access_roles.json', 'w') as convert_file:
            convert_file.write(result)

    return result


# Function Extract info to be more easily callable
def extract_ac_info(roles, domain): 
    defname = f"API : Extract AC Info : {domain}"

    dict_result_ac = json.loads(roles) # json.loads takes a string as input and returns a dictionary as output
    len_json = len(dict_result_ac['objects'])

    new_dict = {} 
    for i in range(len_json): 
        x = dict_result_ac['objects'][i]
        new_dict[i] = x
        if len(sys.argv) > 1 and sys.argv[1] == "-d": 
            with open (f'{domain}_extract_ac_info.json', 'w') as convert_file:
                convert_file.write(json.dumps(new_dict))

    return new_dict, len_json
        

def add_access_roles(user, domain, sid): 

    defname = f"API : Add Access Roles : {domain}"

    ac_url = f'{url}/add-access-role'
    x = sid["sid"]
    headers = {'Content-Type' : 'application/json',
                'X-chkp-sid' : f'{x}'} 

    name = user
    add_any = 'any'
    body = {
                'name' : f'{name}',
                'networks' : f'{add_any}',
                'users' : f'{add_any}',
                'machines' : f'{add_any}',
                'remote-access-clients' : f'{add_any}',
                } 

    api_post = requests.post(ac_url, data=json.dumps(body), headers=headers, verify=False)
    result = api_post.json()

    sleeptime(2)
    publish(domain, sid)

    api_debug(defname, ac_url, headers, body, result, api_post)
    if len(sys.argv) > 1 and sys.argv[1] == "-d":
        with open (f'{domain}_add_access_roles.json', 'a') as convert_file:
         convert_file.write(json.dumps(result))

    
def set_access_role(body, domain, sid): 

    defname = f"API : Set Access Role : {domain}"

    ac_url = f'{url}/set-access-role'
    x = sid["sid"]
    headers = {'Content-Type' : 'application/json',
                'X-chkp-sid' : f'{x}'} 

    api_post = requests.post(ac_url, data=json.dumps(body), headers=headers, verify=False)
    result = api_post.json()
              
    api_debug(defname, ac_url, headers, body, result, api_post)

    sleeptime(2)
    publish(domain, sid)

            
def does_user_exist(role, domain, sid): 

    defname = f"API : Does User Exist : {role} : {domain}"

    ac_url = f'{url}/show-access-role'
    x = sid["sid"]
    headers = {'Content-Type' : 'application/json',
                'X-chkp-sid' : f'{x}'} 
    
    body = {'name' : role}

    api_post = requests.post(ac_url, data=json.dumps(body), headers=headers, verify=False)
    result = api_post.json()

    api_debug(defname, ac_url, headers, body, result, api_post)

    if api_post.status_code == 200: 
        answer = True
        # print(f"\n{answer}\n")
    else: 
        answer = False
        # print(f"\n{answer}\n")

    return answer


def merge_roles(jsonLen, dict, domain, sid):

        for x in range(jsonLen):
            print(f"\n\nCustomer in Line: {x}\n\n")
            user = dict[x]['name']
            yesno = does_user_exist(user, domain, sid)
            if yesno == True: 
                print(f"User exists skipping... {user}\n")
                sleeptime(.5)
            else: 
                print(f"User does not exist adding... {user}\n")
                try:
                    add_user = user
                    add_access_roles(add_user, domain, sid)
                    for y in dict[x]['users']:
                        name = dict[x]['name']
                        source = ad_domain
                        base_dn = y['dn']
                        selection = ldap.dn.explode_rdn(base_dn, flags=ldap.DN_FORMAT_LDAPV2)
                        selection = selection[0].replace('CN=', '')
                        if selection == "Domain_Guests":
                            selection = selection.replace('_', '')

                        setbody = {'name' : f'{name}',
                                    'users' : 
                                        {'add' :
                                            {'source' : f'{source}',
                                            'selection' : f'{selection}',
                                            },
                                        },
                                    }
                        set_access_role(setbody, domain, sid)   

                except Exception as e: 
                    if len(sys.argv) > 1 and sys.argv[1] == "-d":
                        print(f"Error : {e}")


def main(): 
    #Login, gather relevant domains sid's 
    from_sid = api_login(fromDomain)
    to_sid = api_login(toDomain)

    # Gather json response of roles from API
    from_roles = show_access_roles(fromDomain, from_sid)

    # Extract and make roles parsable (add roles is called here)
    extracted_roles, jsonLen = extract_ac_info(from_roles, fromDomain)

    # Run for loop of dictionary and required functions. 
    merge_roles(jsonLen, extracted_roles, toDomain, to_sid)

    # cleanup sid's
    logout(toDomain, to_sid)
    logout(fromDomain, from_sid)

if __name__=="__main__":
    main()




