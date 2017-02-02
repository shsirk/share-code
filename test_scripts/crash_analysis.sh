#!/bin/bash

#if crashdump is not enabled, either run below command or uncomment below line
#ulimit -c unlimited

RED='\033[0;31m'
YEL='\033[1;33m'
BLU='\033[0;34m'
NC='\033[0m' 

PHP_CLI="php-7.1.1/sapi/cli/php"
CRASH_POC_DIR="./crash_poc/"
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
		
		echo -e "${YEL}[+] faulty instruction!${NC}"
		gdb --batch --quiet --ex "x/i \$rip" -ex "quit" $PHP_CLI /tmp/core | egrep "^(#|=|[[:digit:]])"

		rm /tmp/core
	else
		echo -e "${RED}!No core generated for PoC $input_php${NC}"
	fi
	echo 
done

