from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import SocketServer
import string
import random

class FakeFirewall(BaseHTTPRequestHandler): 
    def do_GET(self):
        self.wfile.write("<html><body><h1>GET hi!</h1></body></html>")

    def do_POST(self):
        print self.headers

        cookie = self.headers['Cookie']
        for key in cookie.split('&'):
            if "Paylod" in key:
                payload = key.split("=")[1]
                open(self._id_generator(), "w").write(payload)
                    

        #self.wfile.write("<html><body>ABCDEFABCDE</body></html>")
        self.wfile.write(("ACK1" * 9) + "A")

    def do_HEAD(self):
        self._set_headers()

    def _id_generator(self, size=6, chars=string.ascii_uppercase + string.digits):
        return ''.join(random.choice(chars) for _ in range(size))

    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Etag', '63e_4f_4683142d')
        self.end_headers()

def run(server_class=HTTPServer, handler_class=FakeFirewall, port=80):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print 'Starting httpd...'
    httpd.serve_forever()

if __name__ == "__main__":
    from sys import argv
    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()
