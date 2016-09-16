from difflib import SequenceMatcher
import os

class MatchingBlock:
    def __init__ (self, src_offset, dst_offset, length, text):
        self.src_offset = src_offset
        self.dst_offset = dst_offset
        self.length = length
        self.text   = text
        
        self.match = False
        self.strong_match = False
    
    def __eq__ (self, other):
        if isinstance(other, self.__class__):
            return ( (self.src_offset == other.src_offset) and \
                (self.dst_offset == other.dst_offset) and \
                (self.length == other.length) and \
                (self.text == other.text) )
        else:
            return False
            
    def __str__(self):
        return "##MatchingBlock## src_off %d, dst_off %d, length %d [%s]" % (self.src_offset, self.dst_offset, self.length, self.text)
    
def GetMatchingBlocks(SRC, DST, lo = 10, hi = 1000):
    src_line = ""
    dst_line = ""

    matching_blocks = []
    try:
        with open(SRC, "r") as src, open(DST, "r") as dst:
            src_line = src.read()
            dst_line = dst.read()

        if src_line and dst_line:
            sm = SequenceMatcher(None, src_line, dst_line, False)
        
            for block in sm.get_matching_blocks():
                src_off, dst_off, length = block
                if (length >= lo and length <= hi):
                    matching_blocks.append(MatchingBlock(src_off, dst_off, length, src_line[src_off:src_off+length]))
                
    except IOError:
        print "IOError received"

    return matching_blocks

def main(DIR):
    files = os.listdir(DIR)
    match_map = { }

    full_path = lambda rel_path : os.path.join(os.curdir, DIR, rel_path)
    
    #remove two random files from list
    rand0file, rand1file = files.pop(), files.pop()
    
    matchig_blocks = GetMatchingBlocks(full_path(rand0file), full_path(rand1file))
    if not matchig_blocks:
        print "Serious error, nothing match between two random files!"
    
    while files:
        mblocks = GetMatchingBlocks(full_path(rand0file), (full_path(files.pop())))
        if not mblocks:
            print "WARNING! no match found between (%s <-> %s)" % (full_path(rand0file), (full_path(files.pop())))
        
        for mb0 in matchig_blocks:
            for mb1 in mblocks:
                if (mb0 == mb1):
                    mb0.strong_match = True
                elif ((mb0.length == mb1.length) and (mb0.text == mb1.text)):
                    mb0.match = True

    #finally check the matching blocks:
    for mb in matchig_blocks:
        if (mb.match):
            print "MATCH: %s " % str(mb)
        elif (mb.strong_match):
            print "STRONG MATCH: %s " % str(mb)
            
if __name__ == "__main__":
    from sys import argv
    if (len(argv) == 1):
        print "%s DIR" % argv[0]
    else:
        main(argv[1])
       


