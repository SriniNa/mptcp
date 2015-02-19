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
#define ETHERTYPE_IPV4_OFFSET 14

#define TCP_PROTOCOL 6
#define KEY_SIZE_BYTES 8
#define SHA1_OUT_SIZE_BYTES 20

#define MPTCP_OPTION_TYPE 30
#define ENDOF_OPTION_TYPE 0
#define NOOP_OPTION_TYPE 1

#define MP_CAPABLE_SUBTYPE 0
#define MP_JOIN_SUBTYPE 1
#define ETHER_ADDR_LEN 6

#define WORDS_IN_HMAC_MSG 5

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

    /*
     *  MPTCP option fields token and random in MP_JOIN SYN Msg
     *  in 3-way handshake.
     */
    typedef struct mptcp_join_syn {
        uint32_t client_token;
        uint32_t random_num;
    } mptcp_join_syn_t;


    /*
     *  MPTCP option fields token and random in MP_JOIN SYN_ACK Msg
     *  in 3-way handshake.
     */
    typedef struct mptcp_join_synack {
        uint64_t truncated_hmac;
        uint32_t random_num;
    } mptcp_join_synack_t;

    /*
     *  MPTCP option fields with sender and receiver in MP_CAPABLE
     *  ACK in 3-way handshake.
     */
    typedef struct mptcp_capable_ack {
        uint64_t sender_key;
        uint64_t receiver_key;
    } mptcp_capable_ack_t;


    /*
     *  MPTCP option fields with sender and receiver in MP_CAPABLE
     *  ACK in 3-way handshake.
     */
    typedef struct mptcp_join_ack {
        uint32_t hmac [WORDS_IN_HMAC_MSG];
    } mptcp_join_ack_t;


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

    uint32_t getClientTokenInSyn (mptcp_join_syn_t * joinSyn) {
        return ntohl (joinSyn->client_token);
    }

    uint32_t getRandomInSyn (mptcp_join_syn_t * joinSyn) {
        // No ntohl for random bcoz hmac is computed using network order.
        return joinSyn->random_num;
    }

    uint64_t getTruncatedHmacInSynAck (mptcp_join_synack_t * joinSynAck) {
        return be64toh (joinSynAck->truncated_hmac);
    }

    uint32_t getRandomInSynAck (mptcp_join_synack_t * joinSynAck) {
        // No ntohl for random bcoz hmac is computed using network order.
        return joinSynAck->random_num;
    }

    uint64_t getSenderKey (mptcp_capable_ack_t * capableAck) {
        return be64toh (capableAck->sender_key);
    }

    uint64_t getReceiverKey (mptcp_capable_ack_t * capableAck) {
        return be64toh (capableAck->receiver_key);
    }


    uint32_t getHmacWord (mptcp_join_ack_t* joinAck, int offset) {
        return ntohl(joinAck->hmac[offset]);
    }
} // end mptcp_utils namespace

#endif
