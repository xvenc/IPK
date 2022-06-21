# Packet sniffer

**Name and surname:** Vaclav Korvas

**Login:** xkorva03

Project variation ZETA to course IPK BUT FIT 2022. Packet sniffer, which captures and filters packets on specific interface. According to the command line arguments provided to the program *UDP*, *ARP*, *TCP* or *ICMP* *n*-number of packets are sniffed on specified port. Then the program will print destination and source MAC, IP address and ports to `stdout` with packet data in hexadecimal a ASCII format.

## Build

To build this program use `make` in console. This command will create executable file `ipk-sniffer` in the root folder. To remove the executable and binary files use `make clean`. To successfully build the program you need `make`, `g++` and `pcap library`. Or `make debug` can be used to print additional info about captured packets.

## Usage

```
./ipk-sniffer [-i <interface> | --interface <interface>] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp]} {-n number} {-h|--help}

Options:
    -i, --interface <interface>     Interface that will be sniffed on. 
                                    If empty or not used prints all available interfaces.
    -p <port>                       Filter packets on given port. If not used filter on all ports.
    --tcp, -t                       Show only TCP packets.
    --udp, -u                       Show only UDP packets.
    --arp                           Show only ARP packets.
    --icmp                          Show only ICMP packets.
    -n <number>                     Number of packet to be displayed. If not set one packet is displayed.
    -h, --help                      Print this help message.
    
```

Options in curly brackets are optional. If none of above protocols is set, then implicit all of those protocols above are used. Arguments can be in any order.
Program can be shutdown any time using `Ctrl+C`.

## Implementation details

Destination and source port are not printed when showing *ARP* or *ICMP* packets.
When argument `-i` or `--interface` is used without specific interfaces and some other arguments are used correctly then program will print all interfaces and exits with `return code 0`. But if any argument is used incorrectly the program exits with `return code 1`.
RFC3339 Time zone is listed as Central Europien Summer Time(CEST), UTC +2.
Add `-h` and `--help` arguments to print help message.
To the `Makefile` was added one more option `make debug` as mentioned before. It creates the same executable file but this time it will print more info, for example info about `ICMP packet type` if its response, request etc.

## Examples

```
$./ipk-sniffer --interface eth0 --udp
$./ipk-sniffer -i eth0 -n 10
$./ipk-sniffer -i eth0
$./ipk-sniffer
$./ipk-sniffer -i eth0 --icmp --arp
$./ipk-sniffer -i eth0 -p 22 --tcp --udp --icmp --arp
$./ipk-sniffer -i eth0 -p 22
```

The last two example calls are the same. If the protocol is not specified all protocols are used.

```
$ ./ipk-sniffer
$ ./ipk-sniffer -i             
wlp0s20f3
any
lo
enp4s0
docker0
bluetooth0
```

```
$./ipk-sniffer -i wlp0s20f3 --udp -p 53 
timestamp: 2022-04-13T15:10:34.593+02:00
src MAC: 14:18:c3:81:02:18
dst MAC: 1c:49:7b:da:82:e9
frame length: 92 bytes
src IP: 192.168.1.66
dst IP: 192.168.1.1
src port: 45899
dst port: 53

0x0000: 1c 49 7b da 82 e9 14 18  c3 81 02 18 08 00 45 00 .I{..... ......E.
0x0010: 00 4e d9 47 40 00 40 11  dd c3 c0 a8 01 42 c0 a8 .N.G@.@. .....B..
0x0020: 01 01 b3 4b 00 35 00 3a  83 df 32 65 01 00 00 01 ...K.5.: ..2e....
0x0030: 00 00 00 00 00 00 06 6d  6f 62 69 6c 65 06 65 76 .......m obile.ev
0x0040: 65 6e 74 73 04 64 61 74  61 09 6d 69 63 72 6f 73 ents.dat a.micros
0x0050: 6f 66 74 03 63 6f 6d 00  00 01 00 01             oft.com. ....

```

## Submitted files

* Makefile
* ipk-sniffer.cpp
* ipk-sniffer.h
* manual.pdf
* README.md
