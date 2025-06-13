LDLIBS=-lpcap

all: tls-block

tls-block.o: tls-block.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

iphdr.o: iphdr.h iphdr.cpp

ip.o: ip.h ip.cpp

mac.o: mac.h mac.cpp

tls-block: tls-block.o ip.o mac.o iphdr.o ethhdr.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f tls-block *.o
