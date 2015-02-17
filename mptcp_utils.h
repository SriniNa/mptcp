#ifndef __MPTCP_UTILS_H__

#define __MPTCP_UTILS_H__

#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <inttypes.h>
#include <endian.h>
#include <string>


#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_8021Q 0x8100

#define TCP_PROTOCOL 6
#define KEY_SIZE_BYTES 8
#define SHA1_OUT_SIZE_BYTES 20

#define MPTCP_OPTION_TYPE 30
#define ENDOF_OPTION_TYPE 0
#define NOOP_OPTION_TYPE 1

#define MP_CAPABLE_SUBTYPE 0
#define MP_JOIN_SUBTYPE 1
#define ETHER_ADDR_LEN 6

using namespace std;




namespace mptcp_utils {

    typedef struct ether_header {
        unsigned char ether_dhost [ETHER_ADDR_LEN];
        unsigned char ether_shost [ETHER_ADDR_LEN];
        u_short ether_type;
    } ether_header_t;

    typedef struct tcp_options {
        u_char kind;
        u_char length;
    } tcp_options_t;


    /*
     *  MPTCP Options in TCP Header options field.
     */
    typedef struct mptcp_subtype_version {

#if BYTE_ORDER == BIG_ENDIAN
        u_char mp_subtype:4,
               mp_version:4;
#endif
#if BYTE_ORDER == LITTLE_ENDIAN
        u_char mp_version:4,
               mp_subtype:4;
#endif

        u_char mptcp_flags;

#define MP_H 0x01
#define MP_G 0x02
#define MP_F 0x04
#define MP_E 0x08
#define MP_D 0x10
#define MP_C 0x20
#define MP_B 0x40
#define MP_A 0x80

    } mptcp_subtype_version_t;

    int getEtherType (ether_header_t * etherHeader) {
        return ntohs(etherHeader->ether_type);
    }

    string getSrcIp (struct ip* ipHeader) {
        return string(inet_ntoa(ipHeader->ip_src));
    }


    string getDstIp (struct ip* ipHeader) {
        return string(inet_ntoa(ipHeader->ip_dst));
    }

    int getTotalFragmentLength (struct ip* ipHeader) {
        return ntohs (ipHeader->ip_len);
    }

    int getProtocol (struct ip* ipHeader) {
        return ipHeader->ip_p;
    }

    int getSrcPort (struct tcphdr* tcpHdr) {
        return ntohs(tcpHdr->th_sport);
    }

    int getDstPort (struct tcphdr* tcpHdr) {
        return ntohs(tcpHdr->th_dport);
    }

    unsigned char getTcpFlags (struct tcphdr* tcpHdr) {
        return tcpHdr->th_flags;
    }

    int getTcpHeaderLenInBytes (struct tcphdr* tcpHdr) {
        return tcpHdr->th_off * 4;
    }

    bool isMptcpHflagSet (mptcp_subtype_version_t* mptcp) {
        return ((mptcp->mptcp_flags & MP_H) == 1);
    }

} // end mptcp_utils namespace

#endif
