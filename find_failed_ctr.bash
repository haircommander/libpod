#!/bin/bash 
 
file=$(grep -rl 'copies hosts and resolv' test/e2e/ | grep -v _test) 
# grep 'timed out waiting for file' $file  -B 1 | grep 'in container' | awk 'NF>1{print $NF}' | awk '{print substr($0, 1, 12)}' 
grep -A 1 -B 2 'timed out waiting for file' $file  | grep 'in container' | grep -o "[a-zA-Z0-9]\{64\} " | awk '{print substr($0, 1, 12)}' 

