/*-------------------------------------------------------------*/
/* Exemplo Socket Raw - envio de mensagens                     */
/*-------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>


#include <netinet/ether.h>

#define ETHERTYPE_LEN 2
#define MAC_ADDR_LEN 6
#define BUFFER_LEN 1518

// Atencao!! Confira no /usr/include do seu sisop o nome correto
// das estruturas de dados dos protocolos.

typedef unsigned char MacAddress[MAC_ADDR_LEN];
extern int errno;

struct ip{ // 160b aqui / posso ter 64kB ~ 1500B

unsigned char version;
unsigned char header_lenght;
unsigned char type_of_service;
short int total_lenght;
short int identification;
unsigned char flags;
short int offset;
unsigned char time_to_live;
unsigned char protocol;
short int checksum;
unsigned char source_address[4];
unsigned char destination_address[4];
//unsigned char data[500]; // ~ 4000b aqui de dados


} ip;

struct ipv6_header
{
    unsigned int
        version : 4,
        traffic_class : 8,
        flow_label : 20;
    uint16_t length;
    uint8_t  next_header;
    uint8_t  hop_limit;
    struct in6_addr src;
    struct in6_addr dst;
} ipv6_header;


unsigned short in_cksum(unsigned short *addr,int len)
{
        register int sum = 0;
        u_short answer = 0;
        register u_short *w = addr;
        register int nleft = len;

        /*
         * Our algorithm is simple, using a 32 bit accumulator (sum), we add
         * sequential 16 bit words to it, and at the end, fold back all the
         * carry bits from the top 16 bits into the lower 16 bits.
         */
        while (nleft > 1)  {
                sum += *w++;
                nleft -= 2;
        }

        /* mop up an odd byte, if necessary */
        if (nleft == 1) {
                *(u_char *)(&answer) = *(u_char *)w ;
                sum += answer;
        }

        /* add back carry outs from top 16 bits to low 16 bits */
        sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
        sum += (sum >> 16);                     /* add carry */
        answer = ~sum;                          /* truncate to 16 bits */
        return(answer);
}

int main(int argc, char **argv)
{
  int sockFd = 0, retValue = 0;
  char buffer[BUFFER_LEN], dummyBuf[50]; // 1 char tem 8 bits
  struct sockaddr_ll destAddr;
  struct ip ip_pacote;
  struct ipv6_header ipv6;
  short int etherTypeT = htons(0x8200);

  /* Configura MAC Origem e Destino */
  MacAddress localMac = {0x00, 0x0B, 0xCD, 0xA8, 0x6D, 0x91};
  MacAddress destMac = {0x00, 0x17, 0x9A, 0xB3, 0x9E, 0x16};

  ipv6.version = htons(6);
  ipv6.traffic_class = 0;
  ipv6.flow_label = 0;
  ipv6.length = sizeof(ipv6_header);
  ipv6.next_header = htons(6);
  ipv6.hop_limit = 255;
  inet_pton(AF_INET6, "::1", &(ipv6.src));

  /* Cabecalho IP */

  ip_pacote.version = 4;
  ip_pacote.header_lenght = 12;
  ip_pacote.type_of_service = 0;
  ip_pacote.total_lenght = 5000;
  ip_pacote.flags = 0;
  ip_pacote.protocol = 6; //tcp
  strcpy(ip_pacote.source_address, argv[1]);
  strcpy(ip_pacote.destination_address,argv[2]);
  ip_pacote.checksum = in_cksum((unsigned short*)&ip_pacote, sizeof(ip_pacote));
    

  /* Criacao do socket. Todos os pacotes devem ser construidos a partir do protocolo Ethernet. */
  /* De um "man" para ver os parametros.*/
  /* htons: converte um short (2-byte) integer para standard network byte order. */
  if((sockFd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
    printf("Erro na criacao do socket.\n");
    exit(1);
  }

  /* Identicacao de qual maquina (MAC) deve receber a mensagem enviada no socket. */
  destAddr.sll_family = htons(PF_PACKET);
  destAddr.sll_protocol = htons(ETH_P_ALL);
  destAddr.sll_halen = 6;
  destAddr.sll_ifindex = 2;  /* indice da interface pela qual os pacotes serao enviados. Eh necessario conferir este valor. */
  memcpy(&(destAddr.sll_addr), destMac, MAC_ADDR_LEN);

  /* Cabecalho Ethernet */
  memcpy(buffer, destMac, MAC_ADDR_LEN);
  memcpy((buffer+MAC_ADDR_LEN), localMac, MAC_ADDR_LEN);
  memcpy((buffer+(2*MAC_ADDR_LEN)), &(etherTypeT), sizeof(etherTypeT));

  /* Add some data */
  memcpy((buffer+ETHERTYPE_LEN+(2*MAC_ADDR_LEN)), dummyBuf, 50);

  while(1) {
    /* Envia pacotes de 64 bytes */
    if((retValue = sendto(sockFd, buffer, 64, 0, (struct sockaddr *)&(destAddr), sizeof(struct sockaddr_ll))) < 0) {
       printf("ERROR! sendto() \n");
       exit(1);
    }
    printf("Send success (%d).\n", retValue);
  }
}
