#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include "sniffer-headers.h"
#include "linkedlist.c"

Node *list_http_client, *list_http_server;
Node *list_telnet_client, *list_telnet_server;
Node *list_ftp_client, *list_ftp_server;

void print_hex_ascii_line(const u_char *payload, int len, int offset)
{
	int i;
	int gap;
	const u_char *ch;

	/* print in ascii */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		ch++;
	}
}
/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{
	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

    printf("    Payload Length: %d\n", len);
    printf("    Payload:\n");
	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}
  printf("\n\n");
}

Node* get_new_node(const struct sniff_tcp *tcp, unsigned int size_payload, 
        const u_char *payload) {
    Node *newNode = malloc(sizeof(Node));
    newNode->next = NULL;
    newNode->source_port = ntohs(tcp->th_sport);
    newNode->dest_port = ntohs(tcp->th_dport);
    newNode->ack_no = ntohl(tcp->th_ack);
    newNode->seq_no = ntohl(tcp->th_seq);
    newNode->payload = (unsigned  char*)malloc(size_payload);
    unsigned int l =0;
    for(l=0;l<size_payload;l++) {
        newNode->payload[l] = payload[l];
    }
    newNode->size_payload =size_payload;
    return newNode;
}


void check_and_insert_in_list(unsigned int source_port, unsigned int dest_port, Node *newNode) {
    if(source_port == 80 || dest_port == 80) {
        if(source_port == 80) {
            list_insert(&list_http_server, newNode);
        } else {
            list_insert(&list_http_client, newNode);
        }
    }
    else if(source_port == 23 || dest_port == 23) {
        if(source_port == 23) {
            list_insert(&list_telnet_server, newNode);
        } else {
            list_insert(&list_telnet_client, newNode);
        }
    }
    else if(source_port == 21 || dest_port == 21) {
        if(source_port == 21) {
            list_insert(&list_ftp_server, newNode);
        } else {
            list_insert(&list_ftp_client, newNode);
        }
    }
}

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	static int count = 1;                   /* packet counter */
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const u_char *payload;                    /* Packet payload */

	unsigned int size_ip;
	unsigned int size_tcp;
	unsigned int size_payload;
	
	count++;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	
	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
	if (size_payload > 0) {
        Node *newNode = get_new_node(tcp, size_payload, payload);
        unsigned int source_port = ntohs(tcp->th_sport);
        unsigned int dest_port =ntohs(tcp->th_dport);
        check_and_insert_in_list(source_port, dest_port, newNode);        
	}
}


void list_print(Node *client_list, Node *server_list) {
    Node *client_node = client_list;
    Node *server_node;
    unsigned int serv_seq_no, serv_ack_no ;
    int firstResponse;
    while (client_node) {
        printf("[Client]:---------------------\n");
        printf("    Sequence Number: %u\n",client_node->seq_no);
	    printf("    Acknowledgement Number: %u\n",client_node->ack_no);
        print_payload(client_node->payload, client_node->size_payload);
        server_node =server_list;
        firstResponse = 1;
        while(server_node) {
            if(server_node->ack_no == client_node->seq_no + client_node->size_payload) {
                if(firstResponse == 1) {
                    printf("[Server]:---------------------\n");
                    firstResponse = 0;
                }
                printf("    Sequence Number: %u\n",server_node->seq_no);
	            printf("    Acknowledgement Number: %u\n",server_node->ack_no);
                print_payload(server_node->payload, server_node->size_payload);
                Node *frwdNode = server_node->next;
                list_delete(&server_list, server_node);
                server_node = frwdNode;
            } else {
                server_node = server_node->next;
            }
        }
        client_node = client_node->next;
    }
}

int main(int argc, char **argv)
{

	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "port 21 or port 23 or port 80";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
    list_http_client= list_http_server = NULL;

	if(argc < 2 ) {
	    fprintf(stderr, "Please specify a pcap file for sniffing\n");
		exit(EXIT_FAILURE);
	}
	
	/* open file for sniffing*/
	handle = pcap_open_offline(argv[1], errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open pcap file %s: %s\n", argv[1], errbuf);
		exit(EXIT_FAILURE);
	}

		/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, 0, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);
	
    list_print(list_http_client,list_http_server);
    list_print(list_telnet_client,list_telnet_server);
    list_print(list_ftp_client, list_ftp_server);
	printf("\nCapture complete.\n");

return 0;
}

