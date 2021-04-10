from wsgiref.handlers import format_date_time
from datetime import datetime
from time import mktime
import magic
import hashlib
import itertools
import threading
import socket
import time
import re

class Service(threading.Thread):
    def __init__(self, ip, port, conn, addr, doms, log):
        threading.Thread.__init__(self)
        self.ip = ip
        self.log = log
        self.port = port
        self.conn = conn
        self.addr = addr
        self.doms = doms
    
    @staticmethod
    def do_GET_or_HEAD(self,data):
        lines = data.decode().split('\r\n')
        HEADER = dict()
        for line in lines:
            if line.__contains__('GET') or line.__contains__('HEAD'):
                HEADER['req_type'] = line.split(' ')[0]
                HEADER['get'] = line.split(' ')[1][1:].replace('%20',' ')
                HEADER['httpV'] = line.split(' ')[2]
            elif line.__contains__('ost:'):
                domain = line.split(' ')[1]
                HEADER['dom'] = domain.split(':')[0]
            elif line.__contains__('Connection:'):
                HEADER['con'] = line.split(' ')[1]
            elif line.__contains__('Range:'):
                HEADER['range'] = line.split(': ')[1].split('=')[1]
            elif line.__contains__('User-Agent:'):
                HEADER['brow'] = line.split(': ')[1]
            elif line.__contains__('If-None-Match:'):
                HEADER['none-match'] = line.split(': ')
            
        HEADER['status'] = ' 404 Not Found'
        HEADER['status-code'] = '404'

        if 'dom' in HEADER and HEADER['dom'] in self.doms:
            HEADER['status'] = ' 200 OK'
            HEADER['status-code'] = '200'
        if 'range' in HEADER:
            HEADER['status'] = ' 206 Partial Content' 
            HEADER['status-code'] = '206'

        
        mime = magic.Magic(mime=True)
        respfile = b''
        try:
            with open(HEADER['dom'] + '/' + HEADER['get'], 'rb') as file:
                respfile = file.read()
                if 'range' in HEADER:
                    st = int(HEADER['range'].split('-')[0])
                    end = HEADER['range'].split('-')[1]
                    
                    if end == '':
                        respfile = respfile[int(st):]
                    else:
                        respfile = respfile[int(st):int(end)+1]
                
                     
        except:
            HEADER['status'] = ' 404 Not Found'
            HEADER['status-code'] = '404'
            respfile = b'REQUESTED DOMAIN NOT FOUND'
            pass
        
        hasher = hashlib.md5()
        hasher.update(respfile)
        HEADER['etag'] = hasher.hexdigest()
        if 'none-match' in HEADER:
            if HEADER['none-match'] == HEADER['etag']:
                HEADER['status'] = ' 304 Not Modifed'
                HEADER['status-code'] = '304'

        RESPONSE = HEADER['httpV'].encode() + HEADER['status'].encode() + b'\r\n'
        RESPONSE += b'Content-Length: ' + str(len(respfile)).encode() + b'\r\n'
        RESPONSE += b'Date: ' + str(datetime.now()).encode() + b'\r\n'
        RESPONSE += b'Connection: ' + HEADER['con'].encode() + b'\r\n'
        RESPONSE += b'Accept-Ranges: bytes\r\n'            
        RESPONSE += b'Server: ' + b'mena\r\n'
        RESPONSE += b'ETag: ' + HEADER['etag'].encode() + b'\r\n'
        if HEADER['con'] == 'keep-alive':
            RESPONSE += b'Keep-Alive: ' + b'timeout=5, max=5' + b'\r\n'

        if HEADER['status'] == ' 200 OK':
            RESPONSE += b'Content-Type: ' + str(mime.from_file(HEADER['dom'] + '/' + HEADER['get'])).encode() + b'\r\n'

        RESPONSE += b'\r\n'
        if HEADER['req_type'] == 'GET':
            RESPONSE += respfile
        RESPONSE += b'\r\n'
        
        text = '['+str(time.ctime())+'] ' + str(self.addr[0]) + ' '
        text += HEADER['dom'] + ' /' + HEADER['get'] + ' '
        text += HEADER['status-code'] + ' '
        text += str(len(respfile)) + ' '
        text += HEADER['brow'] + '\n'
        
        if HEADER['status-code'] == '404':
            try:
                with open(self.log + '/error.log', 'a') as file:
                    file.write(text)
            except: pass
        else:
            try:
                with open(self.log + '/' + HEADER['dom'] + '.log', 'a') as file:
                    file.write(text)
            except: pass
                
        return RESPONSE

    def run(self):
        data = b''
        while True:        
            # self.conn.settimeout(5)
            data += self.conn.recv(1024)
            if len(data) < 1024:  break
            # if not data: break
        
        RESPONSE = self.do_GET_or_HEAD(self,data)
        self.conn.sendall(RESPONSE)
        self.conn.close()



            