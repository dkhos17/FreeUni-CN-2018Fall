#!/usr/bin/env python
from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

import struct

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries.

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        # TODO: Load the firewall rules (from rule_filename) here.
        self.Rules = {}
        with open("rules.conf", "r") as f:
            for line in f:
                line = line[:len(line)-1]
                rule = filter(lambda x : len(x) > 0 , line.lower().split(" "))
                if len(rule) != 3 and len(rule) != 4: continue
                if not rule[1] in self.Rules: self.Rules[rule[1]] = []
                self.Rules[rule[1]].append(rule)

        print 'I am supposed to load rules from %s, but I am feeling lazy.' % \
                config['rule']

        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        self.DB = {}
        with open("geoipdb.txt", "r") as f:
            for i, line in enumerate(f):
                line = line[:len(line)-1]
                rule = (line.lower()).split(" ")
                self.DB[i] = (self.get_binary_ip(rule[0]), self.get_binary_ip(rule[1]), rule[2]) 

        self.LOG = {}
        self.DATA = {} 
        self.LAST = {} 

        # TODO: Also do some initialization if needed.

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.

        send_pkt = pkt # save pkt
        IN = pkt_dir == PKT_DIR_INCOMING
        OUT = pkt_dir == PKT_DIR_OUTGOING
        # IP Header
        prt, iph_len ,src_ip, dst_ip = self.encode_IPHeader(pkt)
        if iph_len < 20: return
        else: pkt = pkt[iph_len:]

        # print prt

        if prt == 6: # TCP Header
            fin, seq, ack, tcp_len, src_port, dst_port = self.encode_TCPHeader(pkt)
            if (OUT and dst_port == '80') or (IN and src_port == '80'): # HTTP
                src, dst = (src_ip, src_port), (dst_ip, dst_port)
                self.union_tcp_packets(pkt[tcp_len:], seq, src, dst)           
                if fin == 1: # fin
                    host = self.encode_HTTPHeader(src, dst)
                    self.try_log(self.check_HTTPRules(host), src, dst)

                # print 'http'
            # send if poss.
            if IN and self.try_send(pkt_dir, send_pkt, self.check_TCPRules(src_ip, src_port)): return
            elif OUT and self.try_send(pkt_dir, send_pkt, self.check_TCPRules(dst_ip, dst_port)): return
            # print 'tcp'

        elif prt == 17: # UDP Header
            src_port, dst_port = self.encode_UDPHeader(pkt)
            if (OUT and dst_port == '53') or (IN and src_port == '53'): # DNS
                domain = self.encode_DNSHeader(pkt[8:])
                if self.try_send(pkt_dir, send_pkt, self.check_DNSRules(domain)): return
            # print 'dns'
            # send if poss.
            if IN and self.try_send(pkt_dir, send_pkt, self.check_UDPRules(src_ip, src_port)): return
            elif OUT and self.try_send(pkt_dir, send_pkt, self.check_UDPRules(dst_ip, dst_port)): return
            # print 'udp'


        elif prt == 1: # ICMP Header
            curr_type = self.encode_ICMPHeader(pkt)
            # send if poss.
            if IN and self.try_send(pkt_dir, send_pkt, self.check_ICMPRules(src_ip, curr_type)): return
            elif OUT and self.try_send(pkt_dir, send_pkt, self.check_ICMPRules(dst_ip, curr_type)): return
            # print 'icmp'
        
        # print "sent"
        if IN: self.iface_int.send_ip_packet(send_pkt)
        elif OUT: self.iface_ext.send_ip_packet(send_pkt)

            


    # TODO: You can add more methods as you want.
    def rework_TCPPacket(self, pkt):
        prt,iph_len,src_ip,dst_ip = self.encode_IPHeader(pkt)
        ip_pkt, tcp_pkt = pkt[:iph_len], pkt[iph_len:]
        _,_,_,tcp_len, src_port, dst_port = self.encode_TCPHeader(tcp_pkt)
        ip_pkt = ip_pkt[:12] + ip_pkt[16:20] + ip_pkt[12:16] + ip_pkt[20:]

        seq = struct.unpack('!L', tcp_pkt[4:8])[0] #SEQ
        ack = struct.unpack('!L', tcp_pkt[8:12])[0] #ACK
        tcp_pkt = tcp_pkt[:4] + struct.pack('!L', ack) + struct.pack('!L', seq+1) + tcp_pkt[12:] 

        sum = (~(struct.unpack('!H', tcp_pkt[16:18])[0])) + (1 << 2) + 1 + (1 << 4) 
        while(sum >> 16) > 0:
            sum = (sum & 0xFFFF) + (sum >> 16)
        
        flag = struct.pack('!B', struct.unpack('!B', tcp_pkt[13])[0]+((1<<2)+(1<<4)))
        tcp_pkt = tcp_pkt[:13] + flag + tcp_pkt[14:]
        tcp_pkt = struct.pack('!H', int(dst_port)) + struct.pack('!H', int(src_port)) + tcp_pkt[4:16] + struct.pack('!H', (~sum)&0xFFFF) + tcp_pkt[18:]
        
        pkt = ip_pkt + tcp_pkt
        return pkt

    def rework_DNSPacket(self, pkt):
        prt,iph_len,src_ip,dst_ip = self.encode_IPHeader(pkt)
        ip_pkt, udp_pkt = pkt[:iph_len], pkt[iph_len:iph_len+8]
        udp_pkt = udp_pkt[2:4] + udp_pkt[:2] + udp_pkt[4:]
        ip_pkt = ip_pkt[:12] + ip_pkt[16:20] + ip_pkt[12:16] + ip_pkt[20:]
        
        dns_pkt = pkt[iph_len+8:]
        header, question = dns_pkt[:12], dns_pkt[12:]
        QDCOUNT = struct.unpack('!H', header[4:6])[0]
        if QDCOUNT != 1: return pkt, 'not one Q'
        QR = struct.unpack('!B', header[2])[0]
        QR = QR | (1 << 7)
        header = header[:2] + struct.pack('!B', QR) + header[3:]
        header = header[:4] + struct.pack('!H', 1) + struct.pack('!H',struct.unpack('!H', header[6:8])[0]+1) + header[8:]  
        
        tot = 0
        while True:
            ln, question, tot = struct.unpack('!B', question[:1])[0], question[1:], tot+1
            if ln == 0: break
            question, tot = question[ln:], tot+ln
        
        QTYPE = struct.unpack('!H', question[:2])[0]
        if QTYPE != 1: return pkt, 'not type A'

        QST, TTL = dns_pkt[12:12+tot+4], struct.pack('!L', 1)
        
        ip = '169.229.49.130'.split('.')
        RDATA = struct.pack('!B', int(ip[0])) + struct.pack('!B', int(ip[1]))
        RDATA += struct.pack('!B', int(ip[2])) + struct.pack('!B', int(ip[3]))
        RDLEN = struct.pack('!H', 4)
        ANS = QST + TTL + RDLEN + RDATA

        dns_pkt = header + QST + ANS + dns_pkt[12+tot+4:]

        pseudo = ''
        for x in (src_ip+'.'+dst_ip).split('.'):
            pseudo += struct.pack('!B', int(x))
        
        udp_pkt = udp_pkt[:4] + struct.pack('!H', struct.unpack('!H',udp_pkt[4:6])[0]+len(ANS)) + udp_pkt[6:]
        pseudo += struct.pack('!B', 0) + struct.pack('!B', 17) + udp_pkt[4:6]
        
        data = pseudo + udp_pkt[:6] + struct.pack('!H', 0) + dns_pkt 


        ip_pkt = ip_pkt[:2] + struct.pack('!H', struct.unpack('!H', ip_pkt[2:4])[0] + len(ANS)) + ip_pkt[4:]
        sum = (~(struct.unpack('!H', ip_pkt[10:12])[0])) + len(ANS) 
        while(sum >> 16) > 0:
            sum = (sum & 0xFFFF) + (sum >> 16)

        ip_pkt = ip_pkt[:10] + struct.pack('!H', (~sum)&0xFFFF) + ip_pkt[12:]
        udp_pkt = udp_pkt[:6] + struct.pack('!H', self.checksum(data))

        new_pkt = ip_pkt + udp_pkt + dns_pkt
        return new_pkt, 'deny'

    def encode_IPHeader(self,pkt):
        ln = struct.unpack('!B', pkt[0])[0]
        ln = ln & 15

        protocol = struct.unpack('!B', pkt[9])[0]

        src = struct.unpack('!BBBB', pkt[12:16])
        dst = struct.unpack('!BBBB', pkt[16:20])
        src_ip = str(src[0])+'.'+str(src[1])+'.'+str(src[2])+'.'+str(src[3])
        dst_ip = str(dst[0])+'.'+str(dst[1])+'.'+str(dst[2])+'.'+str(dst[3])
        return protocol, 4*ln, src_ip, dst_ip

    def encode_TCPHeader(self,pkt):
        # syn = (struct.unpack('!B', pkt[13])[0] & 2)
        fin = (struct.unpack('!B', pkt[13])[0] & 1)
        ln = 4*((struct.unpack('!B', pkt[12])[0] >> 4) & 15)
        seq = struct.unpack('!L', pkt[4:8])[0]
        ack = struct.unpack('!L', pkt[8:12])[0]
        return fin, seq, ack, ln ,str(struct.unpack('!H', pkt[:2])[0]), str(struct.unpack('!H', pkt[2:4])[0])

    def encode_UDPHeader(self, pkt):
        return str(struct.unpack('!H', pkt[:2])[0]), str(struct.unpack('!H', pkt[2:4])[0])

    def encode_ICMPHeader(self, pkt):
        return str(struct.unpack('!B', pkt[:1])[0]) 
    
    def encode_DNSHeader(self, pkt):
        pkt = pkt[12:]
        domain = ''
        while True:
            ln, pkt = struct.unpack('!B', pkt[:1])[0], pkt[1:]
            if ln == 0: break

            domain += pkt[:ln] + b'.'
            pkt = pkt[ln:]

        return (domain[:len(domain)-1]).decode()


    def union_tcp_packets(self, pkt, seq, src, dst):
        if len(pkt) == 0: return
        bey = (src, dst)
        key = (min(src,dst), max(src,dst))
        if self.LAST.get(key, seq) < seq:
            return 
        if not key in self.DATA:
            self.DATA[key] = {}

        if dst[1] == '80':
            if self.DATA[key].get('count',0) > 0:
                host = self.encode_HTTPHeader(src, dst)
                self.try_log(self.check_HTTPRules(host), src, dst)
                self.DATA[key]['count'] = 0
                self.LAST[key] = 0

            if not 'REQ' in self.DATA[key]:
                self.DATA[key]['REQ'] = {}
            
            self.DATA[key]['REQ'][seq] = pkt
        elif src[1] == '80':
            if not 'RSP' in self.DATA[key]:
                self.DATA[key]['count'] = self.DATA.get('count', 0) + 1 
                self.DATA[key]['RSP'] = {}
            
            self.DATA[key]['RSP'][seq] = pkt

        self.LAST[key] = seq+len(pkt)+1
        return True
        


    def encode_HTTPHeader(self, src, dst):
        key = (min(src,dst), max(src,dst))
        if not key in self.DATA: return
        self.LOG[key] = {}
        
        # splits request
        def splitRequest(data):
            lines = data.split('\r\n')
            for i, line in enumerate(lines):
                if 'host' in self.LOG[key] and 'mthd-path-vrsn' in self.LOG[key]:
                    break
                lw = line.lower()
                if i == 0:
                    self.LOG[key]['mthd-path-vrsn'] = line
                elif lw.startswith('host:'):
                    self.LOG[key]['host'] = line.split(':')[1][1:]
            
            
        # splits response
        def splitResponse(data): 
            lines = data.split('\r\n')
            for i, line in enumerate(lines):
                if 'status' in self.LOG[key] and 'size' in self.LOG[key]:
                    break
                lw = line.lower()
                if i == 0:
                    self.LOG[key]['status'] = line.split(' ')[1]
                elif lw.startswith('content-length:'):
                    self.LOG[key]['size'] = line.split(':')[1][1:]

        def get_data(method):
            if not method in self.DATA[key]: return 'nan'
            seqs = sorted(self.DATA[key][method].keys())
            data = ''
            for sq in seqs:
                data += self.DATA[key][method][sq]
            del self.DATA[key][method]
            return data
        
        REQ_DATA, RSP_DATA = get_data('REQ'), get_data('RSP')
        if REQ_DATA != 'nan': splitRequest(REQ_DATA)
        if RSP_DATA != 'nan': splitResponse(RSP_DATA)        

        if not 'host' in self.LOG[key]: self.LOG[key]['host'] = '123.45.67.89'
        if not 'size' in self.LOG[key]: self.LOG[key]['size'] = '-1'
        return self.LOG[key]['host']

    
    def checksum(self, pkt):
        checksum = 0
        pkt = bytearray(pkt+struct.pack('!B',0))
        for i in range(0,len(pkt)-1,2):
            checksum += ((pkt[i] << 8) & 0xff00)+(pkt[i+1] & 0xff)
        
        while (checksum >> 16) > 0:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)

        return ~checksum & 0xFFFF

    def get_binary_ip(self, ip):
        if not ip.__contains__("."): return "0"
        bip = ""
        try:
            for x in ip.split("."):
                bip += '{0:08b}'.format(int(x))
        except: pass
        return bip

    def BSearchCountry(self, ip):
        if not ip.__contains__("."): 
            return 'country not found'
        bip = self.get_binary_ip(ip)
        if len(ip) != 32: 
            return 'country not found'
        L,R,I = 0,len(self.DB.keys()),0
        while L <= R:
            M = (L+R)/2
            if self.DB[M][0] <= bip:
                I, L = M, M + 1
            else:
                R = M - 1
        
        if self.DB[I][0] <= bip and bip <= self.DB[I][1]:  
            return self.DB[I][2]
        return 'country not found'


    def cmpr_ip(self, curr_ip, ip):
        if ip == 'any': return True
        if ip == curr_ip: return True
        if ip.__contains__("/"):
            bip1 = self.get_binary_ip(curr_ip)
            bip2, mask = self.get_binary_ip(ip.split("/")[0]), ip.split("/")[1] 
            return bip1[:int(mask)] == bip2[:int(mask)]
        
        return ip == self.BSearchCountry(curr_ip)
        
    def cmpr_port(self, curr_port, port):
        if port == 'any': return True
        if port.__contains__("-"):
            rng = port.split("-")
            return int(rng[0]) <= int(curr_port) and int(curr_port) <= int(rng[1])
        return curr_port == port

    def check_HTTPRules(self, host):
        if not host: return False, 'no match', 'http' 
        for rule in self.Rules.get('http', []):
            if rule[2][0] == '*' and host.endswith(rule[2][1:]):
                return True, rule[0], 'http' 
            if rule[2] == host or self.cmpr_ip(host, rule[2]):
                return True, rule[0], 'http'

        return False, 'no match', 'http'

    def check_DNSRules(self, domain):
        for rule in self.Rules.get('dns',[]):
            if rule[2] == domain: return True, rule[0], 'dns'
            if rule[2][0] == '*' and domain.endswith(rule[2][1:]):
                return True, rule[0], 'dns'

        return False, 'no match', 'dns'
    
    def check_UDPRules(self, curr_ip = "", curr_port = ""):
        for rule in self.Rules.get('udp',[]):
            if rule[2] == 'any' or self.cmpr_ip(curr_ip, rule[2]):
                if rule[3] == 'any' or self.cmpr_port(curr_port, rule[3]):
                    return True, rule[0], 'udp'
        
        return False, 'no match', 'udp'


    def check_TCPRules(self, curr_ip = "", curr_port = "", curr_type = ""):
        for rule in self.Rules.get('tcp',[]):
            if rule[2] == 'any' or self.cmpr_ip(curr_ip, rule[2]):
                if rule[3] == 'any' or self.cmpr_port(curr_port, rule[3]):
                    return True, rule[0], 'tcp'
        
        return False, 'no match', 'tcp'

    def check_ICMPRules(self, curr_ip = "", curr_type = ""):
        for rule in self.Rules.get('icmp',[]):
            if rule[2] == 'any' or self.cmpr_ip(curr_ip, rule[2]):
                if rule[3] == 'any' or rule[3] == curr_type:
                    return True, rule[0], 'icmp'
        
        return False, 'no match', 'icmp'


    def try_log(self, check, src, dst):
        if not check[0]: return False
        key = (min(src,dst), max(src,dst))
        if not key in self.LOG: return False
        if not 'status' in self.LOG[key] or not 'mthd-path-vrsn' in self.LOG[key]:
            if "." in self.LOG[key]['host'] and self.LOG[key]['size'] == '-1':
                return False

        host, size = self.LOG[key]['host'] + ' ', self.LOG[key]['size'] + '\n'
        status = self.LOG[key].get('status', '') + ' '
        mpv = self.LOG[key].get('mthd-path-vrsn', '') + ' '

        log = host + mpv + status + size
        with open('http.log', 'a') as f:
            f.write(log)
            f.flush()
        return True


    def try_send(self, pkt_dir, send_pkt, check):
        # print check
        if not check[0]: return False
    
        if check[1] == 'deny' and check[2] == 'tcp':
            send_pkt = self.rework_TCPPacket(send_pkt)
        elif check[1] == 'deny' and check[2] == 'dns': 
            send_pkt, chk = self.rework_DNSPacket(send_pkt)
            if chk[1] == 'not one Q' or chk[1] == 'not type A': return True
        
        if pkt_dir == PKT_DIR_INCOMING and check[1] == 'deny':
            self.iface_ext.send_ip_packet(send_pkt)
        elif pkt_dir == PKT_DIR_OUTGOING and check[1] == 'deny':
            self.iface_int.send_ip_packet(send_pkt)

        if pkt_dir == PKT_DIR_INCOMING and check[1] == 'pass':
            self.iface_int.send_ip_packet(send_pkt)
        elif pkt_dir == PKT_DIR_OUTGOING and check[1] == 'pass':
            self.iface_ext.send_ip_packet(send_pkt)
        return True


# TODO: You may want to add more classes/functions as well.

