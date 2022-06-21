/*
 * ipk-sniffer.cpp
 * Solution for 2. task for IPK 2021/2022
 * Author: Václav Korvas VUT FIT 2BIT (xkorva03)
 * Main file to sniff packets
 *
 */

#include <cstdlib>
#include "string.h"
#include <cstdio>
#include <iostream>
#include <getopt.h>
#include <ctime>
#include <chrono>
#include "pcap/pcap.h"
#include "arpa/inet.h"
#include "netinet/ether.h"
#include "netinet/ip_icmp.h"
#include "netinet/if_ether.h"
#include "netinet/tcp.h"
#include "netinet/udp.h"
#include "netinet/icmp6.h"
#include "netinet/ip6.h"
#include "ipk-sniffer.h"

char error_buffer[PCAP_ERRBUF_SIZE]; 	//global variable for error message from pcap

// function that prints message to stderr and exits with given ret code
void my_exit(std::string msg, int ret_code) {
	std::cerr << msg << std::endl;
	exit(ret_code);
}

// function to print help message
void print_help() {
	std::cout << "./ipk-sniffer [-i <interface> | --interface <interface>] {-p port}\
 {[--tcp|-t] [--udp|-u] [--arp] [--icmp]} {-n number} {-h|--help}" << std::endl;
	std::cout << "\nOptions:" << std::endl;
	std::cout << "\t-i, --interface <interface>\tInterface that will be sniffed on." << std::endl;
	std::cout << "\t\t\t\t\tIf empty or not used prints all available interfaces." << std::endl;
	std::cout << "\t-p <port>\t\t\tFilter packets on given port. If not use filter on all ports." << std::endl;
	std::cout << "\t--tcp, -t\t\t\tShow only TCP packets." << std::endl;
	std::cout << "\t--udp, -u\t\t\tShow only UDP packets." << std::endl;
	std::cout << "\t--arp\t\t\t\tShow only ARP packets." << std::endl;
	std::cout << "\t--icmp\t\t\t\tShow only ICMP packets." << std::endl;
	std::cout << "\t-n <number>\t\t\tNumber of packet to be displayed. If not set one packet is\
displayed." << std::endl;
}

// function to find all devices (even those that are not active)
// and print them separetly on new line and then exits with success
void print_interface_devices() {
	pcap_if_t *alldevsp;
	int err = pcap_findalldevs(&alldevsp,error_buffer);	

	if (err == -1) my_exit(error_buffer,1);
	
	while (alldevsp != NULL) {
		std::cout << alldevsp->name << std::endl;
		alldevsp = alldevsp->next;
	}	
	
	pcap_freealldevs(alldevsp);
	// after all devices are freed exit with success
	exit(EXIT_SUCCESS);
}

// help function to better parse arguments
int assign_value(char* opt_arg) {
	int c;

	if (!strcmp(opt_arg, "-n")) c = 'n';
	else if (!strcmp(opt_arg, "-p")) c = 'p';
	else if (!strcmp(opt_arg, "-t") || !strcmp(opt_arg, "--tcp")) c = 't';
	else if (!strcmp(opt_arg, "-u") || !strcmp(opt_arg, "--udp")) c = 'u';
	else if (!strcmp(opt_arg, "--arp")) c = ARP;
	else if (!strcmp(opt_arg, "--icmp")) c = ICMP;
	else if (!strcmp(opt_arg, "-h") || !strcmp(opt_arg, "--help")) c = HELP;
	else c = ':';

	return c;
}

// function to parse all supported command line arguments
void parse_arguments(int argc, char** argv, arguments_t* args) {

	const char *short_opts = ":i:p:n:tuh";
	char *ptr;
	int c, opt_index;
	while ((c = getopt_long(argc, argv,short_opts, long_opts,&opt_index)) != -1){
		
		if ((c == 'i' || c == INTERFACE ) && optarg[0] == '-') {

			args->print_interface = true;
			c = assign_value(optarg);
			for (int i = 1; i < argc; i++) {
				if (!strcmp(argv[i], optarg)){
					if (i+1 < argc) {
						optarg = argv[i+1];
					}
				}
			}
		} else if (c == 'i' || c == INTERFACE) {
			
			args->print_interface = false;
			args->interface = optarg;
			continue;
		} 

		if (c == 'h' || c == HELP) {
			print_help();
			exit(EXIT_SUCCESS);

		} else if (c == 't' || c == TCP) args->tcp = true;

		else if (c == 'u' || c == UDP) args->udp = true;

		else if (c == ARP) args->arp = true;

		else if (c == ICMP) args->icmp = true;

		else if (c == 'p'){
			if (optarg[0] == '-') my_exit("Invalid argument", EXIT_FAILURE);
			
			args->port = (u_int16_t)strtol(optarg,&ptr, 10);
			if (*ptr != '\0') {
				my_exit("Wrong port number\n",1);	
			}
			if (args->port < 1 || args->port > 65535) my_exit("Wrong port number", EXIT_FAILURE);

		} else if (c == 'n') {
			if (optarg[0] == '-') my_exit("Invalid argument", EXIT_FAILURE);
			args->number = strtol(optarg,&ptr,10);
			if (*ptr != '\0') {
				my_exit("Wrong number of packets to capture\n",1);	
			}

		} else if (c == ':') {
			if (optopt == 'i' || optopt == INTERFACE) 
				args->print_interface = true;
			else {
				print_help();
				my_exit("Incorrect argument\n", EXIT_FAILURE);
			}
		} else if (c == '?') my_exit("Wrong program argument\n", EXIT_FAILURE);

	}
}

// function to create string to filter traffic for the sniffer filter.
// supported options fort type is port, for proto is arp, tcp and udp
// for dir are non supported options
std::string create_filter(arguments_t* args) {

	std::string expression = "";
	// check if port number wasnt set
	if (args->port == -1) {
		if (args->tcp) {
			expression += "tcp";
		} 
		if (args->udp) { 
			// check if tcp was set before or not
			if (expression != "") expression += " or ";
			expression += "udp";	
		}

	} else {
		if (args->udp) {
			if (expression != "") expression += " or ";
			expression += "(udp and port " + std::to_string(args->port) + ")";

		}
		if (args->tcp) {
			if (expression != "") expression += " or ";
			expression += "(tcp and port " + std::to_string(args->port) + ")";
		}
		if (!args->tcp && !args->udp) {
			if (expression != "") expression += " or ";
			expression += "(tcp and port " + std::to_string(args->port) + ") or (udp and port " + \
						   std::to_string(args->port) + ")";

		}
	}
	// icmp or arp dont support port
	if (args->icmp) { 
		if (expression != "") expression += " or ";
		expression += "icmp6 or icmp";
	}
	if (args->arp) {
		if (expression != "") expression += " or ";
		expression += "arp";
	}		

	// if no option is set and port is set then sniff all packets on this port
	if (!args->arp && !args->icmp && !args->tcp && !args->udp && args->port != -1) {
		expression = "icmp or icmp6 or arp or (udp and port " + std::to_string(args->port) \
					  + ") or (tcp and port " + std::to_string(args->port) + ")"; 
	}
	// program was run only with set interface
	if (!args->arp && !args->icmp && !args->tcp && !args->udp && args->port == -1) {
		expression += "arp or icmp6 or icmp or udp or tcp";
	}

	//std::cout << expression << std::endl;
	return expression;
}

// function to get mac adress from ethernet header
// and store it in dst_addr
std::string store_mac_adress(u_char* adress) {
	char tmp[MAC_ADDRESS_LENGHT];
	std::string s;
	sprintf(tmp, "%02x:%02x:%02x:%02x:%02x:%02x", adress[0], adress[1], adress[2], 
			adress[3], adress[4], adress[5]);
	return s = tmp;
}

// function to get ip adress (src and dest)
std::string store_ip(u_char* arp_ip) {
	std::string addr;
	char tmp_address[16];
	sprintf(tmp_address, "%d:%d:%d:%d", arp_ip[0], arp_ip[1], arp_ip[2], arp_ip[3]);

	return addr = tmp_address;
}

// fucntion to print the whole packet in ascii and hexadecimal format
void print_hex_and_ascii(output_data_t data, const u_char* payload) {
	// print hexadecimal_ascii representation (data is printed in chucks of 16 bytes
	// per line)
	for (int i = 0; i < data.length; i++) {
		// determine if print offset
		if (i % 16 == 0) {
			// check if all first 16 bytes of hexa were printed and print ascii representation
			// of the same data
			if (i >= 16) {
				for (int j = 16; j > 0; j--) {
					if (j % 16 == 8) printf(" ");
					if (std::isprint(payload[i-j])) {
						printf("%c", payload[i-j]);
					} else {
						printf(".");
					}
				}
			}
			printf("\n");
			printf("0x%04x: ", i);
		} else if (i % 16 == 8) printf(" "); // bigger space in the middle

		printf("%02x ",payload[i]);
	}

	// print " " because of the last row ascii symbols padding
	if (data.length % 16 != 0) {
		int padding_len = 16 - (data.length % 16);
		for (int i = padding_len; i > 0; i--) {
			if (i == 9) 
				printf("    ");	
			else 
				printf("   ");	
		}
	}

	// last row ascii symbols
	for (int i = data.length % 16; i > 0; i--) {
		if ((data.length - i) % 16 == 8) printf(" ");
		if (std::isprint(payload[data.length - i])) {
			printf("%c", payload[data.length - i]);
		} else {
			printf(".");
		}
	}
	std::cout << "\n" << std::endl;
}

// function to print desired outpu to stdout
// it prints srd and dst MAC and IP adresses
// and if 'make debug' is used that it prints more debug informations
// then calls function to print whole paket in hexadecimal and ascii format
void put_output(output_data_t data, const u_char* payload) {
	rfc_3339();
	std::cout << "src MAC: " << data.src_mac << std::endl;
	std::cout << "dst MAC: " << data.dest_mac << std::endl;
	std::cout << "frame length: " << data.length << " bytes" << std::endl;
	std::cout << "src IP: " << data.src_ip << std::endl;
	std::cout << "dst IP: " << data.dst_ip << std::endl;
	if (data.src_port != -1 && data.dst_port != -1) {
		std::cout << "src port: " << data.src_port << std::endl;
		std::cout << "dst port: " << data.dst_port << std::endl;
	}
#ifdef DEBUG
	std::cout << "\ntop packet protocol: " << data.packet_type << std::endl;
	if (data.packet_type == "ICMP" || data.packet_type == "ICMPv6")
		std::cout << "icmp type: " << data.icmp_type << std::endl;	
	else if (data.packet_type == "ARP") {
		std::cout << "ARP src MAC: " << data.arp_mac_src << std::endl;
		std::cout << "ARP dst MAC: " << data.arp_mac_dst << std::endl;
	}
#endif /*DEBUG*/

	print_hex_and_ascii(data, payload);
}

// get ipv6 ip address its used to get dst and src as well
// it returns the ip adress as string
std::string get_ipv6_ip(struct in6_addr ip) {
	char ipv6_ip[INET6_ADDRSTRLEN]; // constant taken from arpa/inet.h header file
	std::string ip_to_return;
	inet_ntop(AF_INET6, &(ip), ipv6_ip, INET6_ADDRSTRLEN);
	ip_to_return = ipv6_ip;
	return ip_to_return;
}

// function to procces ipv4 datagram and determine if above is udp or tcp
// and then print info to stdout
void process_ipv6(const u_char* packet, output_data_t data) {
	struct ip6_hdr* ipv6_h; 			// struct for ipv6 header
	struct tcphdr* tcp_h; 				// structure for tcp datagram
	struct udphdr* udp_h; 				// structure for udp datagram
	struct icmp6_hdr* icmpv6_h;

	ipv6_h = (struct ip6_hdr*)(packet + ETHER_SIZE);
	
	// now determine if its tcp or udp
	if (ipv6_h->ip6_ctlun.ip6_un1.ip6_un1_nxt == TCP_PROTOCOL_NUMBER) { 
		// TCP packet
		data.packet_type = "TCP";
		// ipv6 header is always 40 bytes long
		tcp_h = (struct tcphdr*)(packet + ETHER_SIZE + IPV6_HEADER_LENGTH);
		data.src_port = ntohs(tcp_h->th_sport);
		data.dst_port = ntohs(tcp_h->th_dport);
	} else if (ipv6_h->ip6_ctlun.ip6_un1.ip6_un1_nxt == UDP_PROTOCOL_NUMBER) {
		// UDP
		data.packet_type = "UDP";
		udp_h = (struct udphdr*)(packet + ETHER_SIZE + IPV6_HEADER_LENGTH);
		data.src_port = ntohs(udp_h->uh_sport);
		data.dst_port = ntohs(udp_h->uh_dport);
	} else if(ipv6_h->ip6_ctlun.ip6_un1.ip6_un1_nxt == 58) {
		// icmpv6
		data.packet_type = "ICMPv6";
		icmpv6_h = (struct icmp6_hdr*)(packet + ETHER_SIZE + IPV6_HEADER_LENGTH);	
		data.icmp_type = (int)icmpv6_h->icmp6_type;
		
	}

	data.src_ip = get_ipv6_ip(ipv6_h->ip6_src);
	data.dst_ip = get_ipv6_ip(ipv6_h->ip6_dst);
	put_output(data, packet);

}

// function to procces ipv4 datagram and determine if above is udp or tcp
// and then print info to stdout
void process_ipv4(const u_char* packet, output_data_t data) {
	struct ip* ipv4_h; 					// struct for ipv4 frame
	struct tcphdr* tcp_h; 				// structure for tcp datagram
	struct udphdr* udp_h; 				// structure for udp datagram
	struct icmp* icmp_h; 
	
	ipv4_h = (struct ip*)(packet + ETHER_SIZE);

	// determine what datagram is on above ipv4
	if (ipv4_h->ip_p == TCP_PROTOCOL_NUMBER) {
		// its a TCP datagram
		// ipv4 header doesnt have fixed size and needs to be multiplied by 4
		// because its stored in 32-bit words(4 byte words)
		data.packet_type = "TCP ipv4";
		tcp_h = (struct tcphdr*)(packet + ETHER_SIZE + ipv4_h->ip_hl*4);
		data.src_port = ntohs(tcp_h->th_sport);
		data.dst_port = ntohs(tcp_h->th_dport);

	} else if (ipv4_h->ip_p == UDP_PROTOCOL_NUMBER) {
		// its a UDP datagram
		data.packet_type = "UDP ipv4";
		udp_h = (struct udphdr*)(packet + ETHER_SIZE + ipv4_h->ip_hl*4);
		data.src_port = ntohs(udp_h->uh_sport);
		data.dst_port = ntohs(udp_h->uh_dport);

	} else if (ipv4_h->ip_p == 1) {
		// ICMP packet
		data.packet_type = "ICMP";
		icmp_h = (struct icmp*)(packet + ETHER_SIZE + ipv4_h->ip_hl * 4);
		data.icmp_type = (int)icmp_h->icmp_type;
	}
	
	// get ipv4 ip addres
	data.src_ip = inet_ntoa(ipv4_h->ip_src);
	data.dst_ip = inet_ntoa(ipv4_h->ip_dst);
	put_output(data, packet);
}

// inspiration on how to analyse packets taken from: http://yuba.stanford.edu/~casado/pcap/section4.html 
// author: Martin Casado
// No code was taken from here but it served as starting point to write this function to procces packets
// main function to process packets, it determines if above ethernet header is ipv4,ipv6 or arp hedear
// then it will determine what datagram is above ipv4 and ipv6 packet
void process_packet(u_char *args,const struct pcap_pkthdr *packet_header, const u_char* packet) {
	struct ether_header* eth_h; 		// structure for ethernet frame
	struct ether_arp* arp_h;			// structure for arp header frame
	
	// need to be here to supress the warning
	(void)args;
	output_data_t data;
	// set default values for ports
	data.dst_port = -1;
	data.src_port = -1;

	
	data.length = (int)packet_header->len;
	eth_h = (struct ether_header*)(packet);
	// get src and dst mac adresses
	data.src_mac = store_mac_adress(eth_h->ether_shost);
	data.dest_mac = store_mac_adress(eth_h->ether_dhost);
	// ipv6 and ipv4 are for udp and tcp segments
	
	// ethernet encapsulates ipv4, ipv6 or arp and many more but we are interested in these 3
    if (ntohs(eth_h->ether_type) == ETHERTYPE_IPV6) {
		// ipv6 packet
		process_ipv6(packet, data);
		
    } else if (ntohs(eth_h->ether_type) == ETHERTYPE_ARP) {
		// arp packet
		data.packet_type = "ARP";
		arp_h = (struct ether_arp*)(packet + ETHER_SIZE);	
		data.src_ip = store_ip(arp_h->arp_spa);	
		data.dst_ip = store_ip(arp_h->arp_tpa);
		data.arp_mac_src = store_mac_adress(arp_h->arp_sha);
		data.arp_mac_dst = store_mac_adress(arp_h->arp_tha);

		put_output(data, packet);

	} else if (ntohs(eth_h->ether_type) == ETHERTYPE_IP) {
		// ipv4 packet
		process_ipv4(packet, data);	
		
	}

	return;
}

// main code structure to print time 
// taken from here: https://stackoverflow.com/questions/48771851/im-trying-to-build-an-rfc3339-timestamp-in-c-how-do-i-get-the-timezone-offset
// and the author is K.Haskins
// to get milliseconds taken from here:
// https://stackoverflow.com/questions/54325137/c-rfc3339-timestamp-with-milliseconds-using-stdchrono
// the author is Sebastian, the code was modified and was taken only the part to get the time in milliseconds 
// both codes are from stackoverflow and codes on stackoverflow are under CC BY-SA 3.0 licence
// https://creativecommons.org/licenses/by-sa/3.0/deed.cs
//
// function to print time in rfc3339 format
void rfc_3339() {
    time_t now = time(NULL);
    struct tm *tm;
    int off_sign;
    int off;
	// get milliseconds
	const auto new_now = std::chrono::system_clock::now();
	const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(new_now.time_since_epoch()).count() % 1000;

    if ((tm = localtime(&now)) == NULL) {
        exit(EXIT_FAILURE);
    }

    off_sign = '+';
    off = (int) tm->tm_gmtoff;
    if (tm->tm_gmtoff < 0) {
        off_sign = '-';
        off = -off;
    }
    printf("timestamp: %d-%02d-%02dT%02d:%02d:%02d.%03ld%c%02d:%02d",
           tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
           tm->tm_hour, tm->tm_min, tm->tm_sec, millis,
           off_sign, off / 3600, off % 3600);
	std::cout << std::endl;
}
// end of codes taken from:
// https://stackoverflow.com/questions/48771851/im-trying-to-build-an-rfc3339-timestamp-in-c-how-do-i-get-the-timezone-offset
// https://stackoverflow.com/questions/54325137/c-rfc3339-timestamp-with-milliseconds-using-stdchrono




// main idea of code structure and functions usage taken from: https://www.tcpdump.org/pcap.html
// no actual code was taken from here but just to be sure 
// author: Tim Carstens and Guy Harris
// This document is Copyright 2002 Tim Carstens. All rights reserved. Redistribution and use, 
// with or without modification, are permitted provided that the following conditions are met:
// Redistribution must retain the above copyright notice and this list of conditions.
// The name of Tim Carstens may not be used to endorse or promote products derived from 
// this document without specific prior written permission.
int main(int argc, char **argv) {

	arguments_t args = {-1, "", false, false, false, false, 1, true};
	struct bpf_program packet_filter; 	// structure for compiled packet filter
	bpf_u_int32 mask;					// our netmask
	bpf_u_int32 net;					// our IP 

	parse_arguments(argc, argv, &args);
	
	// -i or --interface or -i wasnt set at all was set without argument 
	// prints all interfaces and exits
	if (args.print_interface) {
		std::cerr << "List of all available interfaces:\n" << std::endl;
		print_interface_devices();
	}
	
	if (pcap_lookupnet(args.interface.c_str(), &net, &mask, error_buffer) == -1) {
		std::cerr << "Can't get netmask for device " + args.interface << std::endl; 
		net = 0;
		mask = 0;
	}

	// sniffing in promiscuous mode (non-zero value is set)
	pcap_t* device_handle = pcap_open_live(args.interface.c_str(), BUFSIZ, 1, 100, error_buffer);

	if (device_handle == NULL) 
		my_exit(error_buffer, 1);
	
	// check if device provides ethernet headers
	if (pcap_datalink(device_handle) != DLT_EN10MB) {
		std::cout << "Device " << args.interface << "doesn't provide ethernet headers" << std::endl;
		pcap_close(device_handle);
		my_exit("", 1);
	}
	// creating filter expression according to the program arguments
	std::string expression = create_filter(&args);

	// compile the created filter expression
	if (pcap_compile(device_handle, &packet_filter, expression.c_str(), 0, net) == -1) {
		pcap_close(device_handle);
		my_exit(pcap_geterr(device_handle), 1);
	}
	
	// apply the compiled filter
	if (pcap_setfilter(device_handle, &packet_filter) == -1) {
		pcap_close(device_handle);
		my_exit(pcap_geterr(device_handle), 1);
	}	

	// main loop to capture N packets
	if (pcap_loop(device_handle, args.number, process_packet, 0) == -1) {
		pcap_freecode(&packet_filter);
		pcap_close(device_handle);
		my_exit("pcap_loop failed", 1);
	}

	// close a capture device
	pcap_freecode(&packet_filter);
	pcap_close(device_handle);
	return EXIT_SUCCESS;
}
