#!/usr/bin/env bash

while true; do
	echo "========="
	./psearch.py --trace --debug --client sol.infosec.stonybrook.edu
	read -p "q to quit : " -n 1 -t 5
	[ "${REPLY}" == "q" ] && break
done
