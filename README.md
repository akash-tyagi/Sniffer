Sniffer
=======

Assignment from Security

Files Included:
1. sniffer.c: The actual code used to sniff the pcap files with some code taken from the tutorial site http://www.tcpdump.org/pcap.html site included in the Assignment tutorial links.
2. linkedlist.c : Linked List used to store the tcp data in sorted order based on the sequence number
3. sniffer-header.h : Header file with various predefined ethernet, ip and tcp structures taken from the http://www.tcpdump.org/pcap.html site included in the Assignment tutorual links.

Steps to Execute the Program:
1. Complile the file sniffer.c with other files in the same folder
	gcc sniffer.c -lpcap
2. Execute the file with pcap file as argument
	./a.out <some-pcap-dump-file>
3. Output of various http , telnet and ftp data will be available in the httpData.txt, telnetData.txt and ftpData.txt files in the same folder. Check the output of these files.

Note: Parse only 1 file at a time

Design:

*libpcap 0.8-dev (Packet CAPture) development library is used for this assignment provided in the ubuntu 14.04 which is a system-independent API.

*Predefined libpcap functions are used to parse the pcap dump files. Filter is used on port numbers 21, 23 and 80 to capture ftp, telnet and http packets respectively.

*I have created a linkedlist which is used to store the tcp packets data in sorted order based on the sequence number available in the tcp header. This helps us in ordering the packets as packets can come out of order. 

*It also avoid adding duplicate packets by dropping any packet which has the sequence number as present in the list.

*Two lists are used one is Client list with all the client requests and other is Server list with all the server responses sorted on the sequence number.

Working: 
1. First the pcap file is opened using the offline mode and packets are parsed one by one.
2. Ethernet, IP and TCP packets are extracted from the packet.
3. A new node is created with all the relevant tcp data
4. New node is added the the appropriate linked list based on the port number.
5. All the lists are printed
	
	Requst-Response Printing:
1. First a client node is selected and its corresponding server responses are searched in the server list
2. The server response is found such that the (sequence number of client node + payload = acknowledgement number of the server node)
3. Since response can be fragmented all the server responses with same acknowledgement numbers are printed and removed from the server list to avoid duplicate printing.
4. Since the client and server requests and responses are sorted, this makes the ordering of the packerts easy.


Findings/Debug Experience:
1. HTTP packets can be out of order
2. There can be duplicate HTTP packets
3. Data is non encrytped in HTTP, Telnet and FTP and hence we can even see the password send in case of telnet which is a major security concern.
4. Packet data is in Network byte order and needs to be converted to the host format.
5. Response from Server can come in multiple packets as based on the size limitation of the MTU of ethernet, packet can be fragmented into multple packets with each containing the same acknowledgment number.
6.





