from scapy import *
from scapy.all import *


def get_http_headers(http_payload):
    try:
        headers_raw = http_payload[:http_payload.index("\r\n\r\n")+2]
        headers = dict(re.findall(r'(?P<name>.*?):(?P<value>.*?)\r\n', headers_raw))
    except:
        return None
    if 'Cookie' not in headers:
        return None
    return headers

def extract(PCAP, OUT_DIR):        
    pcap = rdpcap(PCAP)
    
    packet_num = 0
    sessions = pcap.sessions()
    for session in sessions:
        http_payload = ""

        for packet in sessions[session]:
            try:
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    http_payload = str(packet[TCP].payload)
        
                    headers = get_http_headers(http_payload)
                    if headers is None:
                        continue
            
                    cookie = headers['Cookie']
                    for param in cookie.split("&"):
                        if "Payload" in param:
                            payload = param.replace("Payload=", "")
                            open("%s/session_%d" % (OUT_DIR, packet_num) , "w").write(payload)
                            packet_num = packet_num+1
            except:
                pass

def usage():
    print "cmd [-o|--outdir=DIR_PATH] FILE1..."

if __name__ == "__main__":
    from sys import argv, exit
    from getopt import getopt, GetoptError
    args = []
    try:
        opts, args = getopt(argv[1:], "o:h", [ 'outdir=', 'help'])
    except GetoptError:
        exit(1)

    out_dir = "out"
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            usage()
            exit(1)
        elif opt in ('-o', '--outdir'):
            out_dir = arg
        else:
            usage()
            exit(1)

    if not args:
        usage()
        exit(1)

    for arg in args:
        extract(arg, out_dir)

