import socket
import sys
import os
import hashlib

WINAPPDBG_PATH = r".\Frameworks\winappdbg"

try:
  sys.path.append(WINAPPDBG_PATH)
  from winappdbg import win32, Debug, HexDump, Crash
except ImportError:
  sys.exit(1)
  
def download_file_to(src_host, src_port, dst_path):
  print '[+]    downloading testcase'
  client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  try:
    client.connect((src_host, src_port))
    with open(dst_path, "wb") as ofd:
      while 1:
        data = client.recv(4096)
        if not data:
          break
        ofd.write(data)
    client.close()
  except:
    print '[-]    error while downloading'
    return False
  return True
  

TESTCASE_PATH = os.path.join(os.getcwd(), "testcase.bin")

def crash_handler(event):
  if event.get_event_code() == win32.EXCEPTION_DEBUG_EVENT and event.is_last_chance():
    print '[*] crash discovered, saving testcase file'
    with open(TESTCASE_PATH, "rb") as ifd:
      cc = ifd.read()
      m = hashlib.md5()
      m.update(cc)
      with open(os.path.join(os.getcwd(), m.hexdigest()), "wb") as ofd:
        ofd.write(cc)
        
    event.get_process().kill()

def run_within_debugger(args):
  print '[+]    running testcase...'
  with Debug( crash_handler, bKillOnExit = True ) as debug:
    debug.execv( args , bConsole=True)
    debug.loop()
    
def download_testcase_and_test():
  while 1:
    print '[+] running next testcase'
    if download_file_to('localhost', 8080, TESTCASE_PATH):
      run_within_debugger([r"ehx.exe", TESTCASE_PATH])
    print
    
if __name__ == "__main__":
  download_testcase_and_test()
