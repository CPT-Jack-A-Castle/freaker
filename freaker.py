import yaml
import sys
import os
import optparse
from shutil import which
from urllib.parse import urlparse
import concurrent.futures
import random
import validators
import ipaddress
import string

BLUE = '\033[94m'
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CLEAR = '\x1b[0m'

print(BLUE + "Freaker[2.5] by ARPSyndicate" + CLEAR)
print(YELLOW + "automation framework for kenzerdb" + CLEAR)

if len(sys.argv) < 2:
    print(RED + "[!] ./freaker --help" + CLEAR)
    sys.exit()

else:
    parser = optparse.OptionParser()
    parser.add_option('-c', '--config', action="store",
                      dest="config", help="path to configs.yaml")
    parser.add_option('-t', '--target', action="store",
                      dest="target", help="target [default = *]", default="*")
    parser.add_option('-l', '--list-modules', action="store_true", default=False,
                      dest="list", help="returns all modules")
    parser.add_option('-i', '--module-info', action="store",
                      dest="info", help="returns all info about modules")
    parser.add_option('-r', '--run-module', action="store",
                      dest="run", help="runs a module")
    parser.add_option('-T', '--threads', action="store",
                      dest="threads", help="number of concurrent threads [default = 10]", default=10)

inputs, args = parser.parse_args()
ilist = inputs.list
info = str(inputs.info)
rmod = str(inputs.run)
dtarget = str(inputs.target)
threads = inputs.threads
if validators.domain(dtarget.lower()) != True and dtarget.lower() != "monitor" and dtarget.lower() != "*":
    try:
        ipaddress.ip_network(dtarget)
        dtarget = dtarget.replace("/", "#")
    except ValueError:
        print(RED + "[!] invalid target" + CLEAR)
        sys.exit()

if inputs.config:
    CONFIG = str(inputs.config)

try:
    with open(CONFIG) as configs:
        config = yaml.load(configs)
        freakerdb = config['freakerdb']
        kenzerdb = config['kenzerdb']+"directory/"
        workspace = config['kenzerdb']+"file/"
        if(os.path.exists(workspace) == False):
            os.system("mkdir "+workspace)
        print(GREEN + "[*] configurations loaded successfully" + CLEAR)
except Exception as exception:
    print(RED + "[!] invalid configurations" + CLEAR)
    print(exception.__class__.__name__ + ": " + str(exception))
    sys.exit()

try:
    with open(freakerdb+"freakerdb.yaml") as database:
        db = yaml.load(database)
        print(GREEN + "[*] freakerdb loaded successfully" + CLEAR)
        modules = list(db.keys())
except Exception as exception:
    print(RED + "[!] freakerdb could not be loaded" + CLEAR)
    print(exception.__class__.__name__ + ": " + str(exception))
    sys.exit()


def listmodules():
    for module in modules:
        print(module)
    return


def isinstalled(name):
    return which(name) is not None


def getinputs(detection, output):
    detect = detection.split('|')[1]
    location = detection.split('|')[0]
    if location in ['portenum', 'webenum']:
        os.system("cat {0}{4}/{3}.kenz | grep -i ':{1}$' | sort -u | tee -a {2}".format(
            kenzerdb, detect, output, location, dtarget))
    elif location in ['headenum', 'urlheadenum', 'shodscan', 'urlenum']:
        os.system("cat {0}{4}/{3}.kenz | grep -i '{1}' | cut -d ' ' -f 1 | sort -u | tee -a {2}".format(
            kenzerdb, detect, output, location, dtarget))
    elif location in ['servenum']:
        os.system("cat {0}{4}/{3}.kenz | grep -i '\[.*{1}.*\]' | cut -d ' ' -f 2 | sort -u | tee -a {2}".format(
            kenzerdb, detect, output, location, dtarget))
    elif location in ['favscan']:
        os.system("cat {0}{4}/{3}.kenz | grep -i '\t{1}\t' | cut -d '\t' -f 3 | sort -u | tee -a {2}".format(
            kenzerdb, detect, output, location, dtarget))
    elif location in ['cvescan', 'idscan', 'vulnscan', 'buckscan', 'subscan', 'cscan', 'endscan']:
        os.system("cat {0}{4}/{3}.kenz | grep -i '\[{1}\]'| cut -d ' ' -f 2- | sort -u | tee -a {2}".format(
            kenzerdb, detect, output, location, dtarget))
    else:
        print(RED + "[!] invalid detection" + CLEAR)
        sys.exit()


def filterinputs(inputs, output):
    dlist = []
    with open(inputs) as f:
        targets = f.read().splitlines()
    for target in targets:
        if len(target)>0:
            if len(urlparse(target).scheme) > 0:
                dlist.append(
                    "{0}://{1}".format(urlparse(target).scheme, urlparse(target).netloc))
            else:
                dlist.append("{0}".format(target))
    dlist.sort()
    dlist = list(set(dlist))
    with open(output, 'w') as f:
        f.writelines("%s\n" % line for line in dlist)
    os.system("rm "+inputs)


def moduleinfo(command):
    if command in modules:
        print("{1} description: {2} {0}".format(
            db[command]['info'], YELLOW, CLEAR))
        print("{1} input type: {2} {0}".format(
            db[command]['itype'], YELLOW, CLEAR))
        print("{1} requirements: {2} {0}".format(
            db[command]['requires'], YELLOW, CLEAR))
        print("{1} detections: {2} {0}".format(
            db[command]['detections'], YELLOW, CLEAR))
    else:
        print(RED + "[!] module not found" + CLEAR)

cmd = ""
out = ""
def thread_exploit(target):
    global db, freakerdb, out
    os.system("cd {0}{1} && python3 main.py '{2}' '{3}'".format(freakerdb, db[cmd]['path'], target, out+"."+''.join(random.choices(string.ascii_uppercase + string.digits, k=7)))) 

def exploitit(command):
    global out, cmd
    cmd = command
    out = workspace+"{0}.freakout".format(command)
    depends = db[command]['requires'].split(" ")
    run = True
    for elf in depends:
        if(isinstalled(elf) == False):
            print(RED + "[!] `{0}` is not installed".format(elf)+CLEAR)
            run = False
    if run:
        emp = workspace+"{0}.freakem".format(command)
        inp = workspace+"{0}.freakin".format(command)
        detections = db[command]['detections'].split("||")
        for detects in detections:
            getinputs(detects, emp)
        filterinputs(emp, inp)
        if(os.path.exists(out)):
            os.system("mv {0} {0}.old".format(out))
        if db[command]['itype'] == 'single':
            with open(inp) as f:
                targets = f.read().splitlines()            
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                try:
                    executor.map(thread_exploit, targets)
                except(KeyboardInterrupt, SystemExit):
                    print(RED + "[!] interrupted" + CLEAR)
                    executor.shutdown(wait=False)
                    sys.exit()
        else:
            os.system("cd {0}{1} && python3 main.py '{2}' '{3}'".format(freakerdb, db[command]['path'], inp, out))
        os.system("cat {0}.* > {0}".format(out))
        os.system("rm {0}.*".format(out))
        os.system("rm {0}".format(inp))

def runmodule(command):
    if command in modules:
        exploitit(command)
    elif command == "*":
        for coms in modules:
            exploitit(coms)
    else:
        print(RED + "[!] module not found" + CLEAR)


try:
    if ilist:
        listmodules()
        sys.exit()
    elif info != "None":
        moduleinfo(info)
    elif rmod != "None":
        runmodule(rmod)
except KeyboardInterrupt:
    print(RED + "[!] interrupted" + CLEAR)

except Exception as exception:
    print(exception.__class__.__name__ + ": " + str(exception))
    print(RED + "[!] an exception occurred" + CLEAR)