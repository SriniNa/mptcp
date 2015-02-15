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

#define MP_SUBTYPE_CAPABILITY 0
#define MP_SUBTYPE_JOIN 1


using namespace std;




namespace mptcp_utils {

    string getSrcIp (struct ip* ipHeader) {
        return string(inet_ntoa(ipHeader->ip_src));
    }


    string getDstIp (struct ip* ipHeader) {
        return string(inet_ntoa(ipHeader->ip_src));
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

} // end mptcp_utils namespace

#endif
