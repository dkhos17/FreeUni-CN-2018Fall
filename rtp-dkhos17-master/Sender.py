import sys
import getopt

import Checksum
import BasicSender

'''
This is a skeleton sender class. Create a fantastic transport protocol here.
'''
class Sender(BasicSender.BasicSender):
    def __init__(self, dest, port, filename, debug=False, sackMode=False):
        super(Sender, self).__init__(dest, port, filename, debug)
        self.sackMode = sackMode
        self.debug = debug

    @staticmethod
    def split_file(data):
        split_data = list()
        for i in range(0,int(len(data)/1024)):
            split_data.append(data[:1024])
            data = data[1024:]
        
        if data:
           split_data.append(data)

        return split_data


    # Main sending loop.
    def start(self):
      packets_data = self.split_file(self.infile.read())
      #handshake
      #for jobia magram testebistvis while iyos :)
      while True: 
        self.send(self.make_packet('syn', -1, ''))
        ack = self.receive(0.5)
        if ack is None: continue
        _, seqno, _, _ = self.split_packet(ack)
        break

      idx = 0
      WINDOW = dict()
      while idx < len(packets_data):
        for i in range(idx, idx+7):
          if i >= len(packets_data): break
          if WINDOW.get(i, False): continue
          self.send(self.make_packet('dat', i, packets_data[i]))
        
        Fast = dict()
        while True:
          ack_data = self.receive(0.5)
          if ack_data is None: break
          _, seqno, _, _ = self.split_packet(ack_data)
        
          if str(seqno).__contains__(';'): #SACK
              ls = seqno.split(';')
              WINDOW[int(ls[0])-1] = Checksum.validate_checksum(ack_data)
              if WINDOW[int(ls[0])-1]: idx = max(idx,int(ls[0]))
              if ls[0] in Fast: Fast[ls[0]] += 1
              else: Fast[ls[0]] = 1
              if Fast[ls[0]] > 3:
                idx = int(ls[0])
                print('fast1')
                break
              if ls[1].__contains__(',') and WINDOW[int(ls[0])-1]:
                for num in ls[1].split(','):
                  WINDOW[int(num)] = True
              elif len(ls[1]) == 1 and WINDOW[int(ls[0])-1]:
                WINDOW[int(ls[1])] = True
          else: #ACK
            if seqno in Fast: Fast[seqno] += 1
            else: Fast[seqno] = 1
            if Fast[seqno] > 3:
                idx = int(seqno)
                print('fast1')
                break
            WINDOW[int(seqno)-1] = Checksum.validate_checksum(ack_data)
            if WINDOW[int(seqno)-1]: idx = max(idx,int(seqno))
            

      self.send(self.make_packet('fin', idx, ''))
        
'''
This will be run if you run this script from the command line. You should not
change any of this; the grader may rely on the behavior here to test your
submission.
'''
if __name__ == "__main__":
    def usage():
        print "BEARS-TP Sender"
        print "-f FILE | --file=FILE The file to transfer; if empty reads from STDIN"
        print "-p PORT | --port=PORT The destination port, defaults to 33122"
        print "-a ADDRESS | --address=ADDRESS The receiver address or hostname, defaults to localhost"
        print "-d | --debug Print debug messages"
        print "-h | --help Print this usage message"
        print "-k | --sack Enable selective acknowledgement mode"

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                               "f:p:a:dk", ["file=", "port=", "address=", "debug=", "sack="])
    except:
        usage()
        exit()

    port = 33122
    dest = "localhost"
    filename = None
    debug = False
    sackMode = False

    for o,a in opts:
        if o in ("-f", "--file="):
            filename = a
        elif o in ("-p", "--port="):
            port = int(a)
        elif o in ("-a", "--address="):
            dest = a
        elif o in ("-d", "--debug="):
            debug = True
        elif o in ("-k", "--sack="):
            sackMode = True

    s = Sender(dest,port,filename,debug, sackMode)
    try:
        s.start()
    except (KeyboardInterrupt, SystemExit):
        exit()
