import os

def etag_list():
    lines = []
    with open("EGBL.config","r") as fd:
        for line in fd:
            if line.startswith("ETAG"):
                lines.append(line)
    return lines

def lauch():
    CMD = "./egregiousblunder_3.0.0.1 -t 127.0.0.1 -p 80 -l 5432 --ssl 0 --config ./EGBL.config --etag %s --nopen"

    for line in etag_list:
        tag = line.split("=")[1].split(":")[0].strip()
        os.system (CMD % tag)

if __name__ == "__main__":
    from sys import argv
    if (len(argv) == 1):
        for tag in etag_list():
            print tag.strip()
    else:
        lauch()

