
import sys
from sys import argv

RED = "\x1B[31m"
BLK = "\x1B[0m"

def printf(ch):
    sys.stdout.write(ch)
    sys.stdout.flush()
    
def dump_hex(FILE):
    with open(FILE, "r") as fd:
        for line in fd:
            for ch in line:
                if (ord(ch) >= 0x20 and ord(ch) <= 0x7e):
#                    printf(BLK)
                    printf(ch)
                else:
#                    printf(RED)
                    printf( ("%02x" % ord(ch)))
        print ""


if __name__ == "__main__":
    if (len(argv) == 1):
        print "requires file name"
    else:
        dump_hex(argv[1])

