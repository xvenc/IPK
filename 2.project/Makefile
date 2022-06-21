.PHONY = all clean
CXX = g++
CXXFLAGS = -Wall -pedantic -Wextra -g -std=c++11
TARGET=ipk-sniffer
LIBS=-lpcap
NAME = manual

all: $(TARGET)

$(TARGET): $(TARGET).cpp
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS)

debug: $(TARGET).cpp
	$(CXX) -DDEBUG $(CXXFLAGS) $^ -o ipk-sniffer $(LIBS)


doc: 
	pdflatex $(NAME).tex
	pdflatex $(NAME).tex

clean:
	rm -rf *.o $(TARGET) $(NAME).{aux,out,dvi,ps,log,te~,fls,toc}

