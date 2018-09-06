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

def run_within_debugger_with_timeout(args):
  print '[+]    running testcase...'
  with Debug( crash_handler, bKillOnExit = True ) as debug:
    debug.execv( args , bConsole=True)
    System.set_kill_on_exit_mode(True)
    maxTime = time.time() + 15
    while debug and time.time() < maxTime:
      try:
        debug.wait(1000)  # 1 second accuracy
      except WindowsError, e:
        if e.winerror in (win32.ERROR_SEM_TIMEOUT,
                              win32.WAIT_TIMEOUT):
          continue
        raise
      try:
        debug.dispatch()
      finally:
        debug.cont()
        
def download_testcase_and_test():
  while 1:
    print '[+] running next testcase'
    if download_file_to('localhost', 8080, TESTCASE_PATH):
      run_within_debugger_with_timeout([r"ehx.exe", TESTCASE_PATH])
    print
    
if __name__ == "__main__":
  download_testcase_and_test()
