#!/bin/bash

# you can optionally redirect output of this script to file in case count of crash is huge like >100 or so
# this script shall create local file with stack hash, that you can verify later with "unique" command, 
# the unique hash later can be filtered from output of this script to see which files generated unique crashes!

#if crashdump is not enabled, either run below command or uncomment below line
#ulimit -c unlimited

RED='\033[0;31m'
YEL='\033[1;33m'
BLU='\033[0;34m'
NC='\033[0m' 

if [ $# -eq 0 ]
then
	echo -e "This script will require ${RED}Crash PoC Dir${NC} path as input"
	echo -e "Usage - "
	echo -e "$0 <crash_poc_dir>"
	exit
fi

PHP_CLI="php-7.1.1/sapi/cli/php"
CRASH_POC_DIR=$1

STACK_HASH_ALL="./stack_hash_all"

if [ -f "$STACK_HASH_ALL" ]; then
	rm $STACK_HASH_ALL
fi

if [ ! -d $CRASH_POC_DIR ]; then
	echo -e "${RED}Directory does not exists!${NC} Did you gave correct path ${RED}$CRASH_POC_DIR${NC}"
	exit
fi

for input_php in $CRASH_POC_DIR/*
do
	echo -e "${BLU}[*]analyzing crash p0c $input_php${NC}"
	$PHP_CLI $input_php 1>/dev/null
	if [ -f "./core" ]
	then
		mv ./core /tmp/core
		
		#gdb quick analysis
		echo -e "${YEL}[+] stack hash!${NC}"
		gdb --batch --quiet --ex "bt" -ex "quit" $PHP_CLI /tmp/core | grep ^# | egrep -o "[a-zA-Z0-9\._/-]*:[0-9]*$" | md5sum
		gdb --batch --quiet --ex "bt" -ex "quit" $PHP_CLI /tmp/core | grep ^# | egrep -o "[a-zA-Z0-9\._/-]*:[0-9]*$" | md5sum >> $STACK_HASH_ALL
		
		echo -e "${YEL}[+] faulty instruction!${NC}"
		gdb --batch --quiet --ex "x/i \$rip" -ex "quit" $PHP_CLI /tmp/core | egrep "^(#|=|[[:digit:]])"

		rm /tmp/core
	else
		echo -e "${RED}!No core generated for PoC $input_php${NC}"
	fi
	echo 
done

