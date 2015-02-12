#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
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
#include <inttypes.h>
#include <endian.h>
#include <iomanip>
#include <iostream>
#include <string.h>
#include <map>
#include <vector>


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

using namespace std;


class MptcpTuple {

    public:
    string srcIp;
    string dstIp;
    int srcPort;
    int dstPort;

    MptcpTuple () {
    }

    MptcpTuple (string sIp, string dIp, int sPort, int dPort):
        srcIp(sIp), dstIp(dIp), srcPort(sPort), dstPort(dPort) {

    }

    bool operator () (const MptcpTuple &lhs, const MptcpTuple &rhs) const {
        return lhs.srcPort < rhs.srcPort; 
    }

};


map <uint32_t, MptcpTuple> clientTokens;
map <MptcpTuple, uint32_t, MptcpTuple> serverTokens;
map <uint32_t, vector<MptcpTuple> > countSubConnMap;


int main (int argc, char** argv)
{


    pcap_t * pPcap = NULL;
    const unsigned char * readPacket;
    struct pcap_pkthdr pktHeader;
    char errBuffer[PCAP_ERRBUF_SIZE];
    int i = 0;
    int countSyns = 0;


    pPcap = pcap_open_offline(argv[1], errBuffer);
    if (pPcap == NULL) {
        cout << " error opening mptcp file" << endl;
        exit(1);
    }

    for (i = 0; (readPacket = pcap_next(pPcap, &pktHeader)) != NULL; i++) {

        int etherType = ((int) (readPacket[12] << 8) | (int)readPacket[13]);
        int etherOffset = 0;

        if (etherType == 0x0800) {
            etherOffset = 14;
        } else if (etherType == 0x8100) {
            etherOffset = 18;
        } else {
            cout << "unknown ether type "  << etherType << endl;
            continue;
        }
        readPacket += etherOffset;
        struct ip *ipHeader =  (struct ip *) readPacket;
        char *ipSrc = inet_ntoa(ipHeader->ip_src);
        char *ipDst = inet_ntoa(ipHeader->ip_dst);
        readPacket = readPacket + sizeof(struct ip);

        struct tcphdr *tcpHdr = (struct tcphdr *) readPacket;
        unsigned int srcPort = ntohs(tcpHdr->th_sport);
        unsigned int dstPort = ntohs(tcpHdr->th_dport);
        unsigned char tcpFlags = tcpHdr->th_flags;
        int isSyn = (tcpFlags & TH_SYN) ? 1 : 0;
        int isAck = (tcpFlags & TH_ACK) ? 1 : 0;
        unsigned char keySrc[8];
        unsigned char keyDst[8];
        unsigned char * result;
        unsigned char sha1[20];
        
        if (isSyn != 0) {
            countSyns += 1;
            readPacket = readPacket + sizeof(struct tcphdr);
            unsigned char * options = (unsigned char *)readPacket;
            while (1) {
                tcp_options_t * tcpOption = (tcp_options_t *) options;
                if (tcpOption->kind == 0) {
                    break;
                }
                if (tcpOption->kind == 30) {
                    cout << " found mptcp option " << endl;
                    mptcp_subtype_version_t *subtypeVersion =
                            (mptcp_subtype_version_t *) (options + 2);
                    if (subtypeVersion->mp_subtype == 0) {
                        uint64_t *key = (uint64_t *) (options + 4);
                        if (isAck == 0) {
                            memcpy (keySrc, key, 8);
                        } else {
                            memcpy (keyDst, key, 8);
                            SHA1(keyDst, 8, sha1);
                            uint32_t clientToken = 
                                (sha1[0] << 24) | (sha1[1] << 16) | (sha1[2] << 8) | (sha1[3]);
                            cout << " client token is " << clientToken << endl;
                            SHA1(keySrc, 8, sha1);
                            uint32_t serverToken = ntohl(*((uint32_t*)sha1));
                            cout << " server token is " << serverToken << endl;
                            MptcpTuple tuple (string(ipSrc), string(ipDst), srcPort, dstPort);
                            clientTokens[clientToken] = tuple;
                            serverTokens[tuple] = serverToken;
                        }
                    }
                    if (subtypeVersion->mp_subtype == 1 && isAck == 0) {
                        unsigned char *key = (unsigned char *) (options + 4);
                        uint32_t token = ntohl(*((uint32_t*)key));
                        MptcpTuple tuple (string(ipSrc), string(ipDst), srcPort, dstPort);
                        cout << " token during join is " << token << endl;
                        map<uint32_t, vector<MptcpTuple> >::iterator it;
                        it = countSubConnMap.find(token);
                        vector<MptcpTuple> listTuple;
                        if (it != countSubConnMap.end()) {
                            listTuple = it->second;
                        }
                        listTuple.push_back(tuple);
                        countSubConnMap[token] = listTuple;    
                    }
                }
                if (tcpOption->kind == 1) {
                    options = options + 1;
                } else {
                    options = options + tcpOption->length;
                }
            }
        }
    }
    cout << "total syns " << countSyns << endl;
    map<uint32_t, MptcpTuple>::iterator itBegin = clientTokens.begin();
    map<uint32_t, MptcpTuple>::iterator itEnd = clientTokens.end();
    for (;itBegin != itEnd; itBegin++) {
        uint32_t clientToken = itBegin->first;
        MptcpTuple tuple = itBegin->second;
        uint32_t serverToken = serverTokens[tuple];
        map<uint32_t, vector<MptcpTuple> >::iterator it =
                            countSubConnMap.find(clientToken);
        vector<MptcpTuple> listConns = it->second;
        cout << "--------- Conn Details ----- " << endl;
        cout << " ipSrc " << tuple.srcIp;
        cout << " ipDst " << tuple.dstIp;
        cout << " srcPort " << tuple.srcPort;
        cout << " dstPort " << tuple.dstPort << endl;
        cout << " client Token " << clientToken << endl;
        cout << " server Token " << serverToken << endl << endl;
        cout << " num Sub Connections " << listConns.size() << endl;
        for (int j=0; j < listConns.size(); j++) {
            MptcpTuple subTuple = listConns[j];
            cout << " Sub Conn " << (j+1) << " Conn Details ipSrc " << subTuple.srcIp;
            cout << " ipDst " << subTuple.dstIp;
            cout << " srcPort " << subTuple.srcPort;
            cout << " dstPort " << subTuple.dstPort << endl << endl;

        }
        cout << endl << "-----------------------------------" << endl;
    }
}
