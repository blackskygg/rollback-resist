#!/bin/bash

for nl in 10 50 100 150
do
    printf "testing n_loops=$nl, n_pcrs=$1\n";
    ./a.out $nl $1
done
	  
