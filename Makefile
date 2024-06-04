# Makefile

CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++11
LDFLAGS = -lsmbclient -ltalloc

all: sambaclient

sambaclient: main.o
	$(CXX) $(CXXFLAGS) main.o $(LDFLAGS) -o sambaclient

main.o: main.cpp
	$(CXX) $(CXXFLAGS) -c main.cpp -o main.o

clean:
	rm -f sambaclient main.o
