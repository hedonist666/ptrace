#!/bin/bash

make
./t2 &
./a.out -p `pidof ./t2` -f lp
kill `pidof ./t2`
