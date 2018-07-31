#include "my_pcap.h"
#include <stdio.h>
#include <stdlib.h>
// Reference from [1] http://www.tcpdump.org/pcap.html
//                [2] https://www.joinc.co.kr/w/Site/Network_Programing/AdvancedComm/pcap_intro
//                [3] http://www.netmanias.com/ko/post/blog/5372/ethernet-ip-tcp-ip/packet-header-ethernet-ip-tcp-ip

void callback(u_char *p, const struct pcap_pkthdr *pkthdr, const u_char *packet);

int main(int argc, char **argv) {
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE]; // 256
    pcap_t *pcd;
	
    // pcap_lookupdev for setting the device
    dev = argv[1];
    if (dev == NULL) {
	fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
	exit(1);
    }
    //pcap_t *pcap_open_live(char *device, int snaplen, int promisc, int to_ms, char *ebuf)
    pcd = pcap_open_live(dev, BUFSIZ,  0/*NON-PROMISCUOUS*/, -1, errbuf);

    if (pcd == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        exit(1);
    }
    
    /*Ethernet header check*/
    if (pcap_datalink(pcd) != DLT_EN10MB){
	fprintf(stderr, "Device %s doesn't provide Ethernet headers\n", argv[1]);
	return 2;
    }

    // [1] + [2]  Similar with """while(true) pcap_next_ex"""
    // pcap_loop(pcd, 0, callback, NULL);

    while (1) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcd, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
	callback(pcd, &header, &packet);
        printf("%u bytes captured\n", header->caplen);
    }

    pcap_close(pcd);
    return 0;

}

// Ethernet 헤더의 "Ethernet Type", IP 헤더의 "Protocol ID",
// TCP/UDP 헤더의 "Destination Port Number"를 통해 최종 응용(Application)이 무엇인지 확인이 가능

void callback(u_char *p, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	/*
	struct pcap_pkthdr{
		struct timeval ts;	//time stamp
		bpf_u_int32 caplen;	//length of portion present
		bpf_u_int32 len;	//length this packet (off wire)
	};
	*/

	// structure reference from [2]
    struct ether_header *etherHdr; // <netinet/ether.h>
    struct ip *ipHdr; // <netinet/ip.h>
    struct tr0y_tcphdr *tcpHdr; // not in <netinet/tcp.h> , my own tcp_header
    u_int hlen; //tcp header length
    char *data_area;

    printf("-----------------------\n");
    printf("[*] CAPTURE THE PACKET!\n");
    printf("[*] Jacked a packet with length of [%d]\n", pkthdr->len);

    /* ethernet header */
    etherHdr = (struct ether_header*) packet;
    printf("[+] Source MAC       : %s\n", ether_ntoa(etherHdr->ether_shost));
    printf("[+] Destination MAC  : %s\n", ether_ntoa(etherHdr->ether_dhost));
    
    /* IP TIME!!!!!!! */
    if(ntohs(etherHdr->ether_type) != ETHERTYPE_IP) {		// ETHERTYPE_IP 0x0800 : IPv4 protocol
        printf("[-] Non-IP packet\n\n");
        return;
    }
    /* IP header */
    ipHdr = (struct ip*)(packet + SIZE_ETHERNET); // SIZE_ETHERNET 6(dst Mac)+6(src Mac)+2(EtherType) = 14
    // inet_ntoa()는 네트워크 바이트 순서의 32비트 값을 Dotted-Decimal Notation의 주소값으로 변환한다.
    printf("[+] Source IP        : %s\n", inet_ntoa(ipHdr->ip_src));
    printf("[+] Destination IP   : %s\n", inet_ntoa(ipHdr->ip_dst));
	
	/* TCP TIME!!!!!! */
    if(ipHdr->ip_p != IPPROTO_TCP) { // In wireshark, protocol field : 6
        printf("[-] Non-TCP packet\n\n");
        return;
    }
    /* TCP header */
	// ip_hl: ip header length 헤더의 길이는 워드 단위로 나타내며 header length의 값이 5라면 5 x 4바이트 = 20바이트
    tcpHdr = (struct tr0y_tcphdr*)(packet + SIZE_ETHERNET + 4 * ipHdr->ip_hl);
    // TH_OFF 
    hlen = TH_OFF(tcpHdr) * 4;
    //printf("-------hlen %d\n",hlen);
    if(hlen < 20) return; 

    // ntohs
    printf("[+] Source port      : %d\n", ntohs(tcpHdr->th_sport)); //th_sport : src port
    printf("[+] Destination port : %d\n", ntohs(tcpHdr->th_dport)); //th_dport : dst port
    printf("[+] Data             :\n");

    data_area = (u_int8_t *)(packet + SIZE_ETHERNET + 4 * ipHdr->ip_hl + hlen);
    //print data only 16 bytes
    for(int i = 0; i < 16; i++) printf("0x%x ",data_area[i]);

    printf("\n");
}
