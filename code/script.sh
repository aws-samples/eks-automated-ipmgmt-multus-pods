#!/bin/sh
cd /app
echo option $1
python3 -u assign-ip-new-ip6-parallel.py $1  
