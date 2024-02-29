#!/usr/bin/python3

import argparse
import time
import re
from datetime import date
from datetime import datetime
from termcolor import colored as clr
from os import system as cmd
from os import path

### ARGUMENT PARSER
p = argparse.ArgumentParser()
p.add_argument(
        '-l',
        '--list',
        dest="list",
        required=True,
        help="List of root domains."
        )
p.add_argument(
        '-t',
        '--targets',
        dest="targets",
        required=True,
        help="Give the targets i.e. 'twitter,twimg'. Used for gau/waymore."
        )
p.add_argument(
        '-p',
        '--ports',
        dest="ports",
        default=False,
        action="store_true",
        help="Enable portscanning."
        )
p.add_argument(
        '-v',
        '--verbose',
        dest="verb",
        action="store_true",
        help="Print results and errors."
        )
args = p.parse_args()

### FUNCTIONS
def is_dir(dirr):
    # Check if a directory exists
    return path.exists(dirr)

def countlines(file):
    # Check how many lines there is in a file
    with open(file,"r") as f:
        line_count = sum(1 for line in f)
    return line_count

def write_file(ls,file):
    # Write into a file
    with open(file,"w") as f:
        for l in ls:
            f.write(f"{l}\n")

def is_trash(string):
    # If string has trash i.e. ".jpg", then return True
    trash = "\.jpe?g|\.png|\.woff2?|\.gif|\.svg|\.webp|\.css"
    if re.search(trash,string) != None:
        return True
    else:
        return False

def get_regex(regex,text):
    # Getting the regex results
    ls = re.findall(regex,text)
    clean = []
    for l in ls:
        if l not in clean:
            clean.append(l)
    return clean

def hispar(file):
    # Get interesting endpoints and parameters from historic endpoints
    with open(file, "r") as f:
        hist = f.read()

    # Lists of information we need
    parameters = []
    jsfiles = []
    apiendpoints = []
    sensitive = []
    otherfiles = []

    # Get historic JS files
    jsfiles = get_regex("https?://[a-zA-Z0-9\-_/\.]{5,}\.js",hist) # Get .js
    jsfiles.extend(get_regex("https?://[a-zA-Z0-9\-_/\.]{5,}\.mjs",hist)) # Get .mjs
    print("[",clr("INFO","green"),"]","Js files found:",len(jsfiles))
    write_file(jsfiles,"historic/hist-jsfiles.txt")

    # Get other extension based files
    otherfiles = get_regex("https?://[a-zA-Z0-9\-_/\.]{5,}\.(?:xml|txt|json|php|asp|aspx|jsp|jspx)",hist)
    print("[",clr("INFO","green"),"]","Other files found:",len(otherfiles))
    write_file(otherfiles,"historic/hist-otherfiles.txt")

    # Sensitive files
    sensitive = get_regex("https?://[a-zA-Z0-9\-_/\.]{5,}\.(?:sql|config|cfg|env|ini|bak|old|backup|csv|log|zip)",hist)
    print("[",clr("INFO","green"),"]","Sensitive files found:",len(sensitive))
    write_file(sensitive,"historic/hist-sensitive.txt")

    # Get parameters
    params = get_regex(r"(?<=[\?&])\w+(?==)",hist)
    print("[",clr("INFO","green"),"]","Parameters found:",len(params))
    write_file(params,"historic/hist-parameters.txt")

    # Get API endpoints
    apiendpoints = get_regex("/api/[a-zA-Z0-9\-_/\.]+",hist)
    apiendpoints.extend(get_regex("/v[0-9\.]/[a-zA-Z0-9\-_/\.]+",hist))
    print("[",clr("INFO","green"),"]","API endpoints found:",len(apiendpoints))
    write_file(apiendpoints,"historic/hist-apiendpoints.txt")

if __name__ == "__main__":
    # Start of the script
    # Current date
    today = date.today()
    
    # Get subs
    if is_dir("domains"):
        # Subdomain enumeration
        cmd(f"subfinder -dL {args.list} -all -silent | anew -d subs.txt | tee -a domains/newsubs/{today}.txt > /dev/null 2>&1")
        cmd(f"cat domains/newsubs/{today}.txt | anew domains/subs.txt > /dev/null 2>&1")
        cmd("cat domains/subs.txt | dnsx -silent -a -ptr -resp -rl 200 | anew domains/dnsx.txt > /dev/null 2>&1")
        cmd("cat domains/dnsx.txt | cut -d \" \" -f 1 | anew domains/resolved.txt > /dev/null 2>&1")
        cmd("cat domains/dnsx.txt | cut -d \" \" -f 2 | cut -d \"[\" -f 2 | cut -d \"]\" -f 1 | anew domains/ips.txt > /dev/null 2>&1")
        print("[",clr("INFO","green"),"]","Subdomains found:",countlines(f"domains/newsubs/{today}.txt"))

        # Probing stuff
        if args.ports:
            cmd(f"httpx -l domains/resolved.txt -sc -title -cl -vhost -silent -timeout 10 -rl 150 -p 443,8000,8008,8080,8443,8888,8880 | anew domains/probe/{today}.txt > /dev/null 2>&1")
        else:
            cmd(f"httpx -l domains/resolved.txt -sc -title -cl -vhost -silent -timeout 10 -rl 150 | anew domains/probe/{today}.txt > /dev/null 2>&1")

        print("[",clr("INFO","green"),"]","Probed domains:",countlines(f"domains/probe/{today}.txt"))
        cmd(f'cat domains/probe/{today}.txt | cut -d " " -f 1,2,3 | tee domains/changes_new.txt > /dev/null 2>&1')

        new = "{print \"new \" $1 \" \" $2 \" \" $3}"
        old = "{print \"old \" $1 \" \" $2 \" \" $3}"
        cmd(f"cat domains/changes_new.txt | awk '{new}' | tee -a domains/new_tmp.txt > /dev/null 2>&1")
        cmd(f"cat domains/changes_old.txt | awk '{old}' | tee -a domains/old_tmp.txt > /dev/null 2>&1")
        cmd(f"cat domains/probe/{today}.txt | cut -d \" \" -f 1 | tee -a domains/tmp.txt > /dev/null 2>&1")

        all_domains = []
        with open("domains/tmp.txt","r") as f:
            for l in f:
                all_domains.append(l.rstrip())
        for domain in all_domains:
            cmd(f"cat domains/new_tmp.txt | grep -E \"{domain} \" 2>/dev/null | tee -a domains/changes/{today}.txt > /dev/null 2>&1")
            cmd(f"cat domains/old_tmp.txt | grep -E \"{domain} \" 2>/dev/null | tee -a domains/changes/{today}.txt > /dev/null 2>&1")
            cmd(f"echo \"\" | tee -a domains/changes/{today}.txt > /dev/null 2>&1")
        cmd("rm domains/new_tmp.txt")
        cmd("rm domains/old_tmp.txt")
        cmd("rm domains/tmp.txt")
        cmd("rm domains/changes_old.txt")
        cmd("mv domains/changes_new.txt domains/changes_old.txt")

    else:
        # Make directories
        cmd("mkdir domains")
        cmd("mkdir domains/changes")
        cmd("mkdir domains/probe")
        cmd("mkdir domains/newsubs")
        cmd("mkdir historic")

        # Subdomain enumeration
        cmd(f"subfinder -dL {args.list} -all -silent | anew domains/subs.txt > /dev/null 2>&1")
        print("[",clr("INFO","green"),"]","Subdomains found:",countlines(f"domains/subs.txt"))
        cmd("cat domains/subs.txt | dnsx -silent -a -ptr -resp -rl 200 | anew domains/dnsx.txt > /dev/null 2>&1")
        cmd("cat domains/dnsx.txt | cut -d \" \" -f 1 | anew domains/resolved.txt > /dev/null 2>&1")
        print("[",clr("INFO","green"),"]","Subdomains that resolve:",countlines(f"domains/resolved.txt"))
        cmd("cat domains/dnsx.txt | cut -d \" \" -f 2 | cut -d \"[\" -f 2 | cut -d \"]\" -f 1 | anew domains/ips.txt > /dev/null 2>&1")
        print("[",clr("INFO","green"),"]","IP's found:",countlines(f"domains/ips.txt"))

        # Probing stuff
        if args.ports:
            cmd(f"httpx -l domains/resolved.txt -sc -title -cl -vhost -silent -timeout 10 -rl 150 -p 443,8000,8008,8080,8443,8888,8880 | anew domains/probe/{today}.txt > /dev/null 2>&1")
        else:
            cmd(f"httpx -l domains/resolved.txt -sc -title -cl -vhost -silent -timeout 10 -rl 150 | anew domains/probe/{today}.txt > /dev/null 2>&1")

        print("[",clr("INFO","green"),"]","Probed subdomains:",countlines(f"domains/probe/{today}.txt"))
        cmd(f'cat domains/probe/{today}.txt | cut -d " " -f 1,2,3 | tee domains/changes_old.txt > /dev/null 2>&1')

        # Starting historic stuff
        cmd(f"cat domains/probe/{today}.txt | grep 200 | cut -d \" \" -f 1 | tee historic/tar.txt > /dev/null 2>&1")
        cmd("cat historic/tar.txt | gau --subs --o historic/gau-res.txt")
        print("[",clr("INFO","green"),"]","Historic endpoints found:",countlines(f"historic/gau-res.txt"))
        hispar("historic/gau-res.txt")


'''
TODO:
    1. Add small hispar into this tool
'''
