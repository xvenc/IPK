/* 
* hinfosvc.cpp
* Solution IPK-1.project, 11.02.2022
* Author: Vaclav Korvas ,VUT FIT 2BIT (xkorva03)
* Přeloženo: g++ 11.1.0
* Simple server for server-client communication
*/

#include <cstdint>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string>
#include <string.h>

#define MAX_LEN 4096 // max lenght of the read message from socket
#define MAX_INFO 1024 // max lenght of info like hostname, cpu_name etc.

#define ERROR_INTERNAL 1 
#define ERROR_ARGUMENT 2
#define ERROR_SOCKET 9 // error return code if something goes wrong in working with socket

// Print usage if not enoug arguments
void print_help() {
	printf("\nUsage: ./hinfosvc [port number]\n");
}

// function to get cpu name and store it in array, which is send as parametr
void get_cpuname(char* name) {

	FILE *fp = popen("cat /proc/cpuinfo | sed -n 5p | cut -d \":\" -f2- | sed 's/^[ \t]*//' | tr -d '\n'", "r");

	fgets(name,MAX_INFO,fp);
	pclose(fp);
}

// function to calculate cpu load from read info, numbers in array are stored this way:
// [0] is user, [1] is nice, [2] system, [3] idle, [4] iowait, [5] irq, [6] softirq, [7] steal
// [8] guest, [9] guest_nice
// algorithm and more info were taken from:
// https://stackoverflow.com/questions/23367857/accurate-calculation-of-cpu-usage-given-in-percentage-in-linux
double cpu_percentage(unsigned long long* prev_info,unsigned long long* curr_info) {

	unsigned long long PrevIdle = prev_info[3] + prev_info[4];
    unsigned long long Idle = curr_info[3] + curr_info[4];

    unsigned long long PrevNonIdle = prev_info[0] + prev_info[1] + prev_info[2] + prev_info[5] + prev_info[6] + prev_info[7];
    unsigned long long NonIdle = curr_info[0] + curr_info[1] + curr_info[2] + curr_info[5] + curr_info[6] + curr_info[7];

    unsigned long long PrevTotal = PrevIdle + PrevNonIdle;
    unsigned long long Total = Idle + NonIdle;

    unsigned long long totald = Total - PrevTotal;
    unsigned long long idled = Idle - PrevIdle;
	
	double cpu_load = 100 * (double)(totald - idled)/totald;
	return cpu_load;
}

// function to parse numbers from string line and convert it to long and store it
void parse_line(char* line,unsigned long long* info) {
	int cnt = 0;
    char* endptr;
	char* split = strtok(line, " ");
	while ((split = strtok(NULL, " ")) != NULL && cnt < 10) {
        info[cnt++] = strtol(split,&endptr,10);
    }
	return;
}

// function to get first line from /proc/stat to calculate cpu usage
double get_cpuload() {
	FILE *fp = fopen("/proc/stat", "r");
    char buffer[MAX_LEN] = {'\0'};
    fgets(buffer, MAX_LEN, fp);
    fclose(fp);

    unsigned long long prev_info[10] = {0};
    unsigned long long curr_info[10] = {0};
	parse_line(buffer,prev_info);
    
	// sleep for 1 second and read the same info again
	sleep(1);
    fp = fopen("/proc/stat", "r");
    fgets(buffer, MAX_LEN, fp);
    fclose(fp);
	
	parse_line(buffer,curr_info);

	return cpu_percentage(prev_info, curr_info);
}

// function to proccess read http header and send proper http response
// return 0 if success
int proccess_header(char* s, int socket) {
	char message[MAX_LEN] = "HTTP/1.1 200 OK\r\nContent-Type: text/plain;\r\n\r\n";
	char err_message[MAX_LEN] = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain;\r\n\r\n400 Bad Request";
	int err_flag = 0; // flag to determine if wrong request was sent	
	
	char hostname[MAX_INFO] = {'\0'}; // array to store hostname
	char cpu_name[MAX_INFO] = {'\0'}; // array to store cpu_name
	
	//std::string msg = "HTTP/1.1 200 OK\r\nContent-Type: text/plain;\r\n\r\n";
		
	// three http header request to compare read http header with
	const char* header_hostname = "GET /hostname ";
	const char* header_cpu_name = "GET /cpu-name ";
	const char* header_load = "GET /load ";

	if( strncmp(s, header_hostname, strlen(header_hostname)) == 0 )	{
		//FILE *fp = fopen("/etc/hostname","r");
		//fscanf(fp,"%s",hostname);
		//fclose(fp);

		int err = gethostname(hostname, MAX_INFO);
		if ( err < 0 ) {
			fprintf(stderr,"ERROR: Couldnt get hostname.\n");
			return ERROR_INTERNAL;
		}	

		strcat(message,hostname);
	} else if ( strncmp(s,header_cpu_name, strlen(header_cpu_name)) == 0 ) {
		get_cpuname(cpu_name);
		strcat(message,cpu_name);

	} else if ( strncmp(s,header_load, strlen(header_load)) == 0 ) {
		double cpu_load = get_cpuload();		
		std::string load = std::to_string((int)cpu_load);
		strcat(message,load.c_str());
		strcat(message,"%");

	} else {
		err_flag = 1;
	} 
	
	if ( err_flag == 0 ) 
		write(socket, message, strlen(message));
	else
		write(socket, err_message, strlen(err_message));
	// empty all arrays
	memset(hostname,'\0',MAX_INFO);
	memset(cpu_name,'\0',MAX_INFO);

	return 0;
}

// main function of the program
int main(int argc, char** argv) {

	if (argc < 2) {
		fprintf(stderr,"ERROR: Not enough arguments.\n");
		print_help();
		return ERROR_ARGUMENT;
	}
	
	// get port number
	char* endptr = NULL;
	int port_num = strtol(argv[1], &endptr, 10);

	if ( port_num < 0) {
		fprintf(stderr, "ERROR: Port has to be a number in interval (0, %d).\n", UINT16_MAX);
		return ERROR_INTERNAL;
	} else if (port_num > UINT16_MAX) {
		fprintf(stderr, "ERROR: Port has to be a number in interval (0, %d).\n", UINT16_MAX);
		return ERROR_INTERNAL;
	} else if ( *endptr != '\0' ) {
		fprintf(stderr, "ERROR: Port has to be a number in interval (0, %d).\n", UINT16_MAX);
		return ERROR_INTERNAL;
	}

	int server_socket, accept_socket;
    struct sockaddr_in in_address;
    int address_len = sizeof(in_address);
    int opt = 1;
    
    // Creating server socket
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
    	fprintf(stderr, "Couldnt create a socket.\n");
        return(ERROR_SOCKET);
    }

	// setsockopt is optional, but it helps to prevent errors such as: address already in use
	if ( setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt , sizeof(opt)) ) {
		fprintf(stderr, " Error when selecting socekt option.\n");
		return(ERROR_SOCKET);
	}

	// fill the address struct, with given port number and with INADDR_ANY so the 
	// operating system sets it for us, and with AF_INET, because we use IPv4 protocol
    in_address.sin_port = htons(port_num);
    in_address.sin_family = AF_INET;
    in_address.sin_addr.s_addr = INADDR_ANY;
    
    // bind server socket to given port
    if (bind(server_socket, (struct sockaddr*) &in_address, address_len) < 0 ) {
		fprintf(stderr, "Error when binding the socket.\n");
        return(ERROR_SOCKET);
    }

	// set server to passive, listen to the client
    if (listen(server_socket, 1) < 0) {
		fprintf(stderr, "Error when listening.\n");
        return(ERROR_SOCKET);
    }
	
	
	// main loop for accpeting from client
    while(1) {

		// extract the first connection request from the queue and return new socket
        if ((accept_socket = accept(server_socket, (struct sockaddr*) &in_address, (socklen_t*) &address_len)) < 0 ) {
			fprintf(stderr, "Error could accept.\n");
            return(ERROR_SOCKET);
        }
       	// buffer to read the "message" from the socket 
        char buffer[MAX_LEN] = {'\0'};
		int msg_read = read( accept_socket , buffer, MAX_LEN);

		if ( msg_read < 0 ) {
			close(accept_socket);
			fprintf(stderr, "ERROR: Couldn't read from socket.\n");
			return ERROR_SOCKET;
		}	

		// proccess http header to determine which request was send
		int err = proccess_header(buffer, accept_socket);
		if (err > 0) {
			close(accept_socket);
			fprintf(stderr, "ERROR: Header wasn't proccess correctly.\n");
			return ERROR_INTERNAL;
		} 
		memset(buffer, '\0', MAX_LEN);
        close(accept_socket);
    }

	return 0;
}
