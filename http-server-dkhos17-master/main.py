from SockeThread import SockeThread
import threading
import socket
import json
import re
import os


if __name__ == "__main__":
    with open('config.json', 'r') as file:
        data = json.load(file)

    try: os.mkdir('logs')
    except: pass

    server = data['server']
    all = set()
    check = dict()
    try: open(data['log'] + '/error.log', 'x')
    except: pass
    for cln in server:
        try: open(data['log'] + '/' + cln['vhost'] + '.log', 'x')
        except: pass 

        all.add((cln['ip'], cln['port']))
        if not (cln['ip'],cln['port']) in check:
            check[(cln['ip'],cln['port'])] = set()

        check[(cln['ip'],cln['port'])].add(cln['vhost'])

    for sok in all:
        SockeThread(sok[0], sok[1], check, data['log']).start()