from scapy import *
from scapy.all import *

class PcapExtractor:
    def __init__(self, PCAP):
        self.pcap_file = PCAP
        try:
            self.pcap = rdpcap(PCAP)
        except:
            raise "Error: Unable to open! Invalid PCAP %s" % PCAP
    
    # private section 
    def _get_http_headers(self, http_payload, keyToCheck = None):
        try:
            headers_raw = http_payload[:http_payload.index("\r\n\r\n")+2]
            headers = dict(re.findall(r'(?P<name>.*?):(?P<value>.*?)\r\n', headers_raw))
        except:
            return None
        if keyToCheck:
            if 'Cookie' not in headers:
                return None
        return headers

    def get_http_headers(self, keyToCheck = None):
        all_session_headers = []

        sessions = self.pcap.sessions()
        for session in sessions:
            http_payload = ""

            for packet in sessions[session]:
                try:
                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                        http_payload = str(packet[TCP].payload)
            
                        headers = get_http_headers(http_payload, keyToCheck)
                        if headers is None:
                            continue
                        all_session_headers.append(headers)
                except:
                    pass
                
        return all_session_headers

if __name__ == "__main__":
    print "PcapExtractor: no test written! use as lib instead"
    from sys import exit
    exit(1)
