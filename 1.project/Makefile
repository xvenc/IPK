.PHONY = all clean
CXX = g++
CXXFLAGS = -Wall -pedantic -Wextra -g -std=c++11
TARGET=hinfosvc

all: $(TARGET)

hinfosvc: hinfosvc.cpp
	$(CXX) $(CXXFLAGS) $^ -o $@

clean: 
	rm -rf *.o $(TARGET)
