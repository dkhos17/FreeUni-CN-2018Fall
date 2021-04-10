from Service import Service
import threading
import socket

class SockeThread(threading.Thread):
    def __init__(self, ip, port, check, log):
        threading.Thread.__init__(self)
        self.ip = ip
        self.log = log
        self.port = port
        self.check = check
    
    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.ip, self.port))
        s.listen()
        while True:        
            conn, addr = s.accept()
            Service(self.ip, self.port, conn, addr, self.check[(self.ip, self.port)], self.log).start()
        s.close()