all: pcap-test

pcap-test: pcap.o
	g++ -o pcap-test pcap.o -lpcap

pcap.o: pcap.cpp
	g++ -c -o pcap.o pcap.cpp

clean:
	rm -f pcap-test
	rm -f pcap.o

