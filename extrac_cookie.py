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

def extract_attack(PCAP):        
	pcap = rdpcap(PCAP)
	
	sessions = pcap.sessions()
        session_count = 1
	for session in sessions:
                print "[+] sesion known...%d" % session_count
                http_payload = ""

                packet_num = 0
		for packet in sessions[session]:
			try:
				if packet[TCP].dport == 80 or packet[TCP].sport == 80:
					http_payload += str(packet[TCP].payload)
			except:
				pass
		
		        headers = get_http_headers(http_payload)
		        if headers is None:
		            continue
			
		        cookie = headers['Cookie']
                        for param in cookie.split("&"):
                            #print param
                            if "Payload" in param:
                                payload = param.replace("Payload=", "")
                                open("out/session_%d" % packet_num , "w").write(payload)
                                packet_num = packet_num+1


extract_attack("attack.pcap")
