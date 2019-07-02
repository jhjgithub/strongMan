#!/bin/bash

DST_DIR="/var/www/strongMan"

if [ -d "$DST_DIR" ]; then
	echo "stop strongMan"
	systemctl stop strongMan
	sleep 1
	rm -rf $DST_DIR
fi

echo "add target dir: $DST_DIR"
mkdir -p $DST_DIR

echo "copy all files"
cp -r * $DST_DIR

cd $DST_DIR

echo "install service"
./setup.py install
./setup.py add-service


echo "cleaning..."
shopt -s extglob
rm -rf -v !(db_key.txt|env|run.py|secret_key.txt|strongMan)
shopt -u extglob

