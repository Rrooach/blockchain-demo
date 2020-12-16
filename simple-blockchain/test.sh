#!/bin/sh
clang++ -std=c++14 -pthread -lssl -lcrypto -Wall -lboost_system main.cpp
./a.out
