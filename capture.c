#include <stdio.h>
#include <stdlib.h>
#include "my_pcap.h"

// Reference from http://www.tcpdump.org/pcap.html

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet);

int main(int argc, char **argv) {
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE]; // 256
    pcap_t *handle;
    const char* name = "김경민"; 
    printf("[sub26_2017]pcap_test[%s]", name);
	
    // pcap_lookupdev for setting the device
    dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		exit(1);
	}
    //pcap_t *pcap_open_live(char *device, int snaplen, int promisc, int to_ms, char *ebuf)
    handle = pcap_open_live(dev, BUFSIZ,  0/*NON-PROMISCUOUS*/, -1, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        exit(1);
    }

    pcap_loop(handle, 0, callback, NULL);
}



void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	/*
	struct pcap_pkthdr{
		struct timeval ts;	//time stamp
		bpf_u_int32 caplen;	//length of portion present
		bpf_u_int32 len;	//length this packet (off wire)
	};
	*/

	// structure reference from https://www.joinc.co.kr/w/Site/Network_Programing/AdvancedComm/pcap_intro#AEN81
    struct ether_header *etherHdr; // <netinet/ether.h>
    struct ip *ipHdr; // <netinet/ip.h>
    struct tcphdr *tcpHdr; // <netinet/tcp.h>

    printf("CAPTURE PACKET!\n");
	printf("Jacked a packet with length of [%d]\n", pkthdr->len);

    /* ethernet header */
    etherHdr = (struct ether_header*) packet;
    printf("Source MAC       : %s\n", ether_ntoa(etherHdr->ether_shost));
    printf("Destination MAC  : %s\n", ether_ntoa(etherHdr->ether_dhost));
    
    /* IP TIME!!!!!!! */
    if(ntohs(etherHdr->ether_type) != ETHERTYPE_IP) {		// ETHERTYPE_IP 0x0800 : IPv4 protocol
        printf("Non-IP packet\n\n");
        return;
    }
    /* IP header */
    ipHdr = (struct ip*)(packet + SIZE_ETHERNET); // SIZE_ETHERNET 6(Dest Mac)+6(Src Mac)+2(EtherType) = 14
    printf("Source IP        : %s\n", inet_ntoa(ipHdr->ip_src));
    printf("Destination IP   : %s\n", inet_ntoa(ipHdr->ip_dst));
	
	/* TCP TIME!!!!!! */
    if(ipHdr->ip_p != IPPROTO_TCP) {
        printf("Non-TCP packet\n\n");
        return;
    }
    /* TCP header */
	// ip_hl: ip header length
    tcpHdr = (struct tcphdr*)(packet + SIZE_ETHERNET + 4*ipHdr->ip_hl);
    printf("Source port      : %d\n", ntohs(tcpHdr->th_sport));
    printf("Destination port : %d\n", ntohs(tcpHdr->th_dport));


    printf("\n");
}
