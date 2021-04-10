import sys
import socket
import struct
import binascii
import ipaddress
from struct import *
from easyzone import easyzone
from easyzone.zone_check import ZoneCheck

def make_off_sets(s):
    offset = b''
    for part in s.split('.'):
        offset += (len(part)).to_bytes(1, 'big')
        if not part: break
        offset += part.encode()
    return offset

def make_answer(QName, QType, QClass, TTL, RData, ANS):
    ANSWER = b'\xc0\x0c'
    ANSWER += struct.pack('!h', QType)
    ANSWER += struct.pack('!h', QClass)
    ANSWER += struct.pack('!i', TTL)
    ANSWER += struct.pack('!h', len(RData))
    ANSWER += RData
    return ANSWER, ANS+1


def askRoot(request, ip, sock):
    sock.sendto(request, (ip,53))
    data, addr = sock.recvfrom(4096)
    s = struct.unpack('! H 5h', data[:12])
    auto, adit = s[4], s[5]
    if s[3] != 0:
        return data

    _, questions, _ = readQName(data, data[12:])
    questions = questions[4:]
    QName = 'none'
    for _ in range(auto):
        _, questions, _ = readQName(data, questions)
        questions = questions[10:]
        QName, questions, _ = readQName(data, questions)
    
    print_ip = ip
    ip = 'none'
    for _ in range(max(0,adit-1)):
        _, questions, _ = readQName(data, questions)
        QType = struct.unpack('!h', questions[:2])[0]
        questions = questions[8:]
        rlen = struct.unpack('!h', questions[:2])[0]
        r_data = questions[2:]
        r_data = r_data[:rlen]
        questions = questions[(2+rlen):]
        if QType == 1:
            ip = str(ipaddress.IPv4Address(r_data))
            break
    
    print('QUESTION SECTION: {}   128   IN   Type: {}   {}'
        .format(QName, 'A', print_ip))
    if ip == 'none':
        new_request = request[:8]
        new_request += struct.pack('!h', 0)
        new_request += struct.pack('!h', 0)
        new_request += make_off_sets(QName)
        new_request += struct.pack('!h', 1)
        new_request += struct.pack('!h', 1)
        new_data = askRoot(new_request, '198.41.0.4', sock)

        _, questions, _ = readQName(new_data, new_data[12:])
        questions = questions[4:]
        _, questions, _ = readQName(data, questions)
        questions = questions[8:]
        rlen = struct.unpack('!h', questions[:2])[0]
        r_data = questions[2:]
        r_data = r_data[:rlen]
        ip = str(ipaddress.IPv4Address(r_data))

    
    return askRoot(request, str(ip), sock)

def readQName(data, questions):
    host, tot = b'', 0
    
    while True:
        if questions[0] >= 192:
            ptr = struct.unpack('!H', questions[:2])[0]
            ptr = ptr^(49152)
            h,_ ,_ = readQName(data, data[ptr:])
            return host.decode() + h, questions[2:], tot+2
        
        n = struct.unpack('!B', questions[:1])[0]
        questions = questions[1:]
        tot += (n+1)
        if n == 0: break
        host += questions[:n]
        host +=  b'.'
        questions = questions[n:]

    return host.decode(), questions, tot


def createSocket():
    new_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    new_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    return new_sock


def run_dns_server(CONFIG, IP, PORT):
    sock = createSocket()
    sock.bind((IP, int(PORT)))

    idx = 0
    CACHER = dict()
    ROOT = ['198.41.0.4', '199.7.91.13']

    while True:
        data, address = sock.recvfrom(4096)
        print('starting up on {} port {}'.format(IP, PORT))

        s = struct.unpack('! H 5h', data[:12])
        ID, QR = s[0], s[1]
        QN, ANS = s[2],s[3]
        questions = data[12:]

        QName, questions, tot = readQName(data, questions)
        QType, questions = struct.unpack('!h', questions[:2])[0], questions[2:]
        QClass, questions = struct.unpack('!h', questions[:2])[0], questions[2:]        
        print('QUESTION SECTION: {}   Type:{}  128   IN  {}'.format(QName, QType, IP))

        key = (QName, QType)
        if key in CACHER:
            RESP = data[:2] + CACHER[key]
            sock.sendto(RESP, address)
            continue
        
        local = True
        RESPONSE, ALL_ANSWERS = b'', b''       
        try: 
            ez = easyzone.zone_from_file(QName[:-1], CONFIG + QName + 'conf')
        except:
            local = False

        if QType == 1: #A
            if local:
                for ip in ez.root.records('A').items: 
                    RDATA = ipaddress.IPv4Address(ip).packed
                    ANSWER, ANS = make_answer(QName, QType, QClass, 0, RDATA, ANS)
                    ALL_ANSWERS += ANSWER
            else:
                RESPONSE = askRoot(data, ROOT[idx], createSocket())
                CACHER[key] = RESPONSE[2:]   
                sock.sendto(RESPONSE, address)            
                continue
        elif QType == 2: #NS
            if local:
                for ns in ez.root.records('NS').items:
                    RDATA = make_off_sets(ns)
                    ANSWER, ANS = make_answer(QName, QType, QClass, 128, RDATA, ANS)
                    ALL_ANSWERS += ANSWER
            else:
                RESPONSE = askRoot(data, ROOT[idx], createSocket())
                CACHER[key] = RESPONSE[2:]                
                sock.sendto(RESPONSE, address)
                continue
        elif QType == 5: #CName 
            if local:
                for cn in ez.root.records('CNAME').items:
                    RDATA = make_off_sets(cn)
                    ANSWER, ANS = make_answer(QName, QType, QClass, 10, RDATA, ANS)
                    ALL_ANSWERS += ANSWER
            else:
                RESPONSE = askRoot(data, ROOT[idx], createSocket())
                CACHER[key] = RESPONSE[2:]
                sock.sendto(RESPONSE, address)
                continue    
        elif QType == 6: #SOA
            if local:
                soa = ez.root.records('SOA').items[0].split(' ')
                RDATA = make_off_sets(soa[0])
                RDATA += make_off_sets(soa[1])
                RDATA += int(soa[2]).to_bytes(4, 'big')
                RDATA += int(soa[3]).to_bytes(4, 'big')
                RDATA += int(soa[4]).to_bytes(4, 'big')
                RDATA += int(soa[5]).to_bytes(4, 'big')
                RDATA += int(soa[6]).to_bytes(4, 'big')
                ANSWER, ANS = make_answer(QName, QType, QClass, 10, RDATA, ANS)
                ALL_ANSWERS += ANSWER
            else:
                RESPONSE = askRoot(data, ROOT[idx], createSocket())
                CACHER[key] = RESPONSE[2:]
                sock.sendto(RESPONSE, address)   
                continue
        elif QType == 15: #MX
            if local:
                for mx in ez.root.records('MX').items:
                    RDATA = mx[0].to_bytes(2, 'big')
                    RDATA += make_off_sets(mx[1])
                    ANSWER, ANS = make_answer(QName, QType, QClass, 10, RDATA, ANS)
                    ALL_ANSWERS += ANSWER
            else:
                RESPONSE = askRoot(data, ROOT[idx], createSocket())
                CACHER[key] = RESPONSE[2:]
                sock.sendto(RESPONSE, address)  
                continue

        elif QType == 16: #TXT
            if local:
                txt = ez.root.records('TXT').items[0].encode()
                RDATA = len(txt).to_bytes(1, 'big') + txt
                ANSWER, ANS = make_answer(QName, QType, QClass, 10, RDATA, ANS)
                ALL_ANSWERS += ANSWER
            else:
                RESPONSE = askRoot(data, ROOT[idx], createSocket())
                CACHER[key] = RESPONSE[2:]
                sock.sendto(RESPONSE, address)
                continue
        elif QType == 28: #AAAA
            if local:
                for ip in ez.root.records('AAAA').items:
                    RDATA = ipaddress.IPv6Address(ip).packed
                    ANSWER, ANS = make_answer(QName, QType, QClass, 10, RDATA, ANS)
                    ALL_ANSWERS += ANSWER
            else:
                RESPONSE = askRoot(data, ROOT[idx], createSocket())
                sock.sendto(RESPONSE, address) 
                CACHER[key] = RESPONSE
                continue
        if local:QR = 33920
        else:QR = 33792

        RESPONSE += data[:2]
        RESPONSE += struct.pack('!H', QR)
        RESPONSE += struct.pack('!h', QN)
        RESPONSE += struct.pack('!h', ANS)
        RESPONSE += data[8:]
        RESPONSE = RESPONSE[:(16+tot)]
        RESPONSE += ALL_ANSWERS

        if data:
            CACHER[key] = RESPONSE[2:]
            sent = sock.sendto(RESPONSE, address)
            print('sent {} bytes back to {}'.format(
                sent, address))
    pass

# do not change!
if __name__ == '__main__':
    CONFIG = sys.argv[1]
    IP = sys.argv[2]
    PORT = sys.argv[3]
    run_dns_server(CONFIG, IP, PORT)