/*
 * ipk-sniffer.h
 * Solution for 2. task for IPK 2021/2022
 * Author: Václav Korvas VUT FIT 2BIT (xkorva03)
 * Header file for ipk-sniffer.cpp with structures and functions declarations
 *
 */

#include <string>
#include <getopt.h>
// insurance that the header file will be included once
#ifndef _IPK_SNIFFER_H_
#define _IPK_SNIFFER_H_

#define ETHER_SIZE 14 			// because ethernet headers are always 14 bytes long
#define INTERFACE 40 			// defines used in getopt_long what will getopt_long return
#define HELP 41
#define TCP 42
#define UDP 43
#define ARP 44
#define ICMP 45
#define MAC_ADDRESS_LENGHT 18	// define mac address length
#define TCP_PROTOCOL_NUMBER 6 	// int number of TCP protocol
#define UDP_PROTOCOL_NUMBER 17 	// int number of UDP protocol
#define IPV6_HEADER_LENGTH 40 	// ipv6 header has fixed size of 40 bytes	

// structure for program arguments
typedef struct {
	int port; 					// variable to store port number
	std::string interface; 	    // variable to store interface 
	bool tcp; 				    // variable to determine if we sniff tcp packets
	bool udp; 					// variable to determine if we sniff udp packets
	bool icmp; 					// variable to determine if we sniff icmp packets
	bool arp; 					// variable to determine if we sniff arp packets
	int number; 				// variable to store how many packets we sniff	
	bool print_interface;
} arguments_t;

// structure for all neccessary output data
typedef struct {
	std::string src_mac;
	std::string dest_mac;
	std::string src_ip;
	std::string dst_ip;
	int src_port;
	int dst_port;
	int length;
	std::string packet_type; 	// sereves to better debug
	int icmp_type; 		 		// serves to better debug of icmp packets
	std::string arp_mac_src; 	// better debug info
	std::string arp_mac_dst; 	// better debug info
} output_data_t;

// struct for function getopt_long, for long commandl line arguments
const struct option long_opts[] = {
	{"interface", 1, 0, INTERFACE},
	{"tcp", 0, 0, TCP},
	{"udp", 0, 0, UDP},
	{"arp", 0, 0, ARP},
	{"icmp", 0, 0, ICMP},
	{"help", 0, 0, HELP},
	{0,0,0,0}
};

// function that prints message to stderr and exits with given return code
void my_exit(std::string msg, int ret_code);

// function to print help message to stdout and exits with return code 0
void print_help();

// function to find all devices (even those that are not active)
// and print them separetly on new line and then exits with success
void print_interface_devices();

// function to parse all supported command line arguments
// args is structure to encapsulate all arguments
void parse_arguments(int argc, char** argv, arguments_t* args);

// function to create string to filter traffic for the sniffer filter
// supported protocols are ICMP, ICMPv6, UDP, TCP and ARP
// for TCP and UDP is possible port option
std::string create_filter(arguments_t* args);

// function to get mac adress from ethernet header
// or from the arp header
std::string store_mac_adress(u_char* adress);

// function to get ip adress use to get source and destination ip address
std::string store_ip(u_char* arp_ip);

// fucntion to print the whole packet in ascii and hexadecimal format
void print_hex_and_ascii(output_data_t data, const u_char* payload);

// function to print desired outpu to stdout
// it prints srd and dst MAC and IP adresses
// then calls function to print whole paket in hexadecimal and ascii format
void put_output(output_data_t data, const u_char* payload);

// get ipv6 ip address its used to get dst and src as well
// it returns the ip adress as string
std::string get_ipv6_ip(struct in6_addr ip);

// function to procces ipv4 datagram and determine if above is udp or tcp
// and then print info to stdout
void process_ipv6(const u_char* packet, output_data_t data);

// function to procces ipv4 datagram and determine if above is udp or tcp
// and then print info to stdout
void process_ipv4(const u_char* packet, output_data_t data);

// main function to process packets, it determines if above ethernet header is
// ipv4,ipv6 or arp hedear then it will determine what datagram is above ipv4 and ipv6 packet
void process_packet(u_char *args,const struct pcap_pkthdr *packet_header, const u_char* packet);

// function to print time in rfc3339 format
void rfc_3339();

#endif
