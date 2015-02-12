#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>


typedef struct tcp_options {
    u_char kind;
    u_char length;
} tcp_options_t;

typedef struct mptcp_subtype_version {

#if BYTE_ORDER == BIG_ENDIAN
    u_char mp_subtype:4,
           mp_version:4;
#endif
#if BYTE_ORDER == LITTLE_ENDIAN
    u_char mp_version:4,
           mp_subtype:4;
#endif

} mptcp_subtype_version_t;

int main (int argc, char** argv)
{


    pcap_t * pPcap = NULL;
    const unsigned char * readPacket;
    struct pcap_pkthdr pktHeader;
    char errBuffer[PCAP_ERRBUF_SIZE];
    int i = 0;
    int countSyns = 0;

    printf ("entering main \n");


    pPcap = pcap_open_offline(argv[1], errBuffer);
    if (pPcap == NULL) {
        printf (" error opening mptcp file");
        exit(1);
    }

    for (i = 0; (readPacket = pcap_next(pPcap, &pktHeader)) != NULL; i++) {
        //printf ("processing %d packet \n", i);
        //printf (" size of packet header is %d \n", pktHeader.len);

        int etherType = ((int) (readPacket[12] << 8) | (int)readPacket[13]);
        int etherOffset = 0;

        if (etherType == 0x0800) {
            etherOffset = 14;
            //printf ("ether type IP \n");
        } else if (etherType == 0x8100) {
            etherOffset = 18;
            //printf ("ether type 802.1q \n");
        } else {
            printf ("unknown ether type \n");
            continue;
        }
        readPacket += etherOffset;
        struct ip *ipHeader =  (struct ip *) readPacket;
        char *ipSrc = inet_ntoa(ipHeader->ip_src);
        //printf (" source address %s \n", ipSrc);
        //printf (" dest address %s \n", (char *) inet_ntoa(ipHeader->ip_dst));
        //int ipHdrLen = ipHeader->ip_hl * 4; // IP Header in words
        readPacket = readPacket + sizeof(struct ip);

        struct tcphdr *tcpHdr = (struct tcphdr *) readPacket;
        unsigned int srcPort = ntohs(tcpHdr->th_sport);
        unsigned int dstPort = ntohs(tcpHdr->th_dport);
        unsigned char tcpFlags = tcpHdr->th_flags;
        int isSyn = (tcpFlags & TH_SYN) ? 1 : 0;
        if (isSyn != 0) {
            countSyns += 1;
            printf ("source port %u \n", srcPort);
            printf ("dst port %u \n", dstPort);
            printf ("tcp flags is SYN %d \n", isSyn);
            readPacket = readPacket + sizeof(struct tcphdr);
            unsigned char * options = (unsigned char *)readPacket;
            while (1) {
                tcp_options_t * tcpOption = (tcp_options_t *) options;
                printf ("tcpoption kind %d \n", tcpOption->kind);
                if (tcpOption->kind == 0) {
                    break;
                }
                if (tcpOption->kind == 1) {
                    options = options + 1;
                    continue;
                }
                if (tcpOption->kind == 30) {
                    printf (" found mptcp optioni \n");
                    mptcp_subtype_version_t *subtypeVersion =
                            (mptcp_subtype_version_t *) (options + 2);
                    printf("subtype is %u \n", subtypeVersion->mp_subtype);
                }
                options = options + tcpOption->length;
            }
        }
    }
    printf ("total syns %d \n", countSyns);

}
