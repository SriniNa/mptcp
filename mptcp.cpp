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

    string srcIp;
    string dstIp;
    int srcPort;
    int dstPort;

    public:
    MptcpTuple () {
    }

    MptcpTuple (string sIp, string dIp, int sPort, int dPort):
        srcIp(sIp), dstIp(dIp), srcPort(sPort), dstPort(dPort) {

    }

    bool operator () (const MptcpTuple &lhs, const MptcpTuple &rhs) const {
        return lhs.srcPort < rhs.srcPort; 
    }

    string getSrcIp () {
        return srcIp;
    }

    string getDstIp () {
        return dstIp;
    }

    int getSrcPort () {
        return srcPort;
    }

    int getDstPort () {
        return dstPort;
    }
};


class CryptoForToken {

    public:
    virtual
    void generateToken (unsigned char * key, int keyLen, unsigned char *out) {
    }

};


class Sha1ForToken: public CryptoForToken {
    public:
    virtual
    void generateToken (unsigned char * key, int keyLen, unsigned char *out) {
        SHA1(key, keyLen, out);
    }

};

class ProcessPcap {
    private:
    map <uint32_t, MptcpTuple> clientTokens;
    map <MptcpTuple, uint32_t, MptcpTuple> serverTokens;
    map <MptcpTuple, vector<unsigned char>, MptcpTuple> keySrcMap;
    map <uint32_t, vector<MptcpTuple> > countSubConnMap;
    map <MptcpTuple, uint32_t, MptcpTuple > subConnMap;
    map <uint32_t, uint64_t> connDataMap;
    map <MptcpTuple, uint64_t, MptcpTuple> subConnDataMap;
    CryptoForToken *crypto;


    public:
    void processPcapFile (const char * fileName, const char * crypto);
    void printMptcpConns ();

};


int main (int argc, char** argv)
{

    if (argc < 2) {
        cout << " please specify pcap file to open" << endl;
        exit(1);
    }
    ProcessPcap pcap;
    if (argc > 2) {
        pcap.processPcapFile (argv[1], argv[2]);
    } else {
        pcap.processPcapFile (argv[1], NULL);
    }
    pcap.printMptcpConns ();
}


void
ProcessPcap::processPcapFile (const char * fileName, const char * cryptoName) {

    char errBuffer[PCAP_ERRBUF_SIZE];
    pcap_t * pPcap = NULL;
    const unsigned char * readPacket;
    const unsigned char * packetStart;
    const unsigned char * headerEnd;
    const unsigned char * tcpheaderEnd;
    struct pcap_pkthdr pktHeader;
    int i = 0;
    int countSyns = 0;

    pPcap = pcap_open_offline(fileName, errBuffer);
    if (pPcap == NULL) {
        cout << " error opening mptcp file" << endl;
        exit(1);
    }

    if (cryptoName == NULL) {
        // default sha1
        crypto = new Sha1ForToken ();
    } else {
        // add new crypto class derived from CryptoForToken
        cout << " add support for new crypto " << endl;
        exit (1);
    }

    for (i = 0; (readPacket = pcap_next(pPcap, &pktHeader)) != NULL; i++) {

        int etherType = ((int) (readPacket[12] << 8) | (int)readPacket[13]);
        int etherOffset = 0;

        if (etherType == 0x0800) {
            etherOffset = 14;
        } else if (etherType == 0x8100) {
            etherOffset = 18;
        } else {
            continue;
        }
        packetStart = readPacket;
        readPacket += etherOffset;
        struct ip *ipHeader =  (struct ip *) readPacket;
        string ipSrc = string(inet_ntoa(ipHeader->ip_src));
        string ipDst = string(inet_ntoa(ipHeader->ip_dst));
        uint64_t totalLength = ntohs(ipHeader->ip_len) * 4;
        int protocol = ipHeader->ip_p; 
        readPacket = readPacket + sizeof(struct ip);

        if (protocol != 6) {
            continue;
        }

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
        int tcpHeaderLength = tcpHdr->th_off * 4;
        tcpheaderEnd = readPacket + tcpHeaderLength;
        uint64_t headerLength = (uint64_t) tcpheaderEnd - (uint64_t) (packetStart);
        uint64_t dataLength = totalLength - headerLength;

        if (isSyn == 0) {
            MptcpTuple tuple (ipSrc, ipDst, srcPort, dstPort);
            MptcpTuple revTuple (ipDst, ipSrc, dstPort, srcPort);
            uint64_t currentData = 0;
            uint32_t token;
            if (subConnDataMap.find(tuple) != subConnDataMap.end()) {
                currentData = subConnDataMap[tuple];
                subConnDataMap[tuple] = currentData + dataLength;
                token = subConnMap[tuple];
            } else {
                currentData = subConnDataMap[revTuple];
                subConnDataMap[revTuple] = currentData + dataLength;
                token = subConnMap[revTuple];
            }
            currentData = 0;
            currentData = connDataMap[token];
            connDataMap[token] = currentData + dataLength;
        } else if (isSyn != 0) {
            countSyns += 1;
            readPacket = readPacket + sizeof(struct tcphdr);
            unsigned char * options = (unsigned char *)readPacket;
            while (1) {
                tcp_options_t * tcpOption = (tcp_options_t *) options;
                if (options >= tcpheaderEnd) {
                    break;
                }
                if (tcpOption->kind == 0) {
                    break;
                }
                if (tcpOption->kind == 30) {
                    mptcp_subtype_version_t *subtypeVersion =
                            (mptcp_subtype_version_t *) (options + 2);
                    if (subtypeVersion->mp_subtype == 0) {
                        uint64_t *key = (uint64_t *) (options + 4);
                        if (isAck == 0) {
                            memcpy (keySrc, key, 8);
                            MptcpTuple tuple (ipSrc, ipDst, srcPort, dstPort);
                            subConnDataMap[tuple] = dataLength;
                            keySrcMap[tuple] = vector<unsigned char> (keySrc, keySrc + 8);
                        } else {
                            MptcpTuple tuple (ipSrc, ipDst, srcPort, dstPort);
                            MptcpTuple revTuple (ipDst, ipSrc, dstPort, srcPort);
                            memcpy (keyDst, key, 8);
                            crypto->generateToken(keyDst, 8, sha1);
                            uint32_t clientToken = 
                                (sha1[0] << 24) | (sha1[1] << 16) | (sha1[2] << 8) | (sha1[3]);
                            vector <unsigned char> keySource = keySrcMap[revTuple];
                            for (int k=0; k < 8; k++) {
                                keySrc[k] = keySource[k];
                            }
                            crypto->generateToken(keySrc, 8, sha1);
                            uint32_t serverToken = ntohl(*((uint32_t*)sha1));
                            cout << " server token is " << serverToken << endl;
                            clientTokens[clientToken] = revTuple;
                            serverTokens[tuple] = serverToken;
                            subConnMap[tuple] = clientToken;
                            subConnMap[revTuple] = clientToken;
                            if (subConnDataMap.find(revTuple) != subConnDataMap.end()) {
                                uint64_t currentData = subConnDataMap[revTuple];
                                uint64_t connCurrentData = connDataMap[clientToken];
                                connDataMap [clientToken] = connCurrentData + currentData + dataLength;
                                subConnDataMap [revTuple] = currentData + dataLength;
                            } 
                        }
                    } else if (subtypeVersion->mp_subtype == 1 && isAck == 0) {
                        unsigned char *key = (unsigned char *) (options + 4);
                        uint32_t token = ntohl(*((uint32_t*)key));
                        MptcpTuple tuple (ipSrc, ipDst, srcPort, dstPort);
                        MptcpTuple revTuple (ipDst, ipSrc, dstPort, srcPort);
                        cout << " token during join is " << token << endl;
                        map<uint32_t, vector<MptcpTuple> >::iterator it;
                        it = countSubConnMap.find(token);
                        vector<MptcpTuple> listTuple;
                        if (it != countSubConnMap.end()) {
                            listTuple = it->second;
                        }
                        listTuple.push_back(tuple);
                        countSubConnMap[token] = listTuple;
                        subConnMap[tuple] = token;
                        subConnMap[revTuple] = token;
                        subConnDataMap [tuple] = dataLength;
                        uint64_t currentData = 0;
                        if (connDataMap.find(token) != connDataMap.end()) {
                            currentData = connDataMap[token];
                        }
                        connDataMap [token] = dataLength + currentData;
                    } else if (subtypeVersion->mp_subtype == 1 && isAck == 1) {
                        MptcpTuple revTuple (ipDst, ipSrc, dstPort, srcPort);
                        uint64_t currentData = 0;
                        uint32_t token = subConnMap[revTuple];
                        if (connDataMap.find(token) != connDataMap.end()) {
                            currentData = connDataMap[token];
                            connDataMap [token] = dataLength + currentData;
                        }
                        currentData = 0;
                        if (subConnDataMap.find(revTuple) != subConnDataMap.end()) {
                            currentData = subConnDataMap[revTuple];
                            subConnDataMap [revTuple] = currentData + dataLength;
                        }
                    }
                }
                if (tcpOption->kind == 1) {
                    options = ((unsigned char *)options) + 1;
                } else {
                    options = ((unsigned char *)options) + tcpOption->length;
                }
            }
        }
    }
    cout << "total syns " << countSyns << endl;

}

void
ProcessPcap::printMptcpConns () {

    map<uint32_t, MptcpTuple>::iterator itBegin = clientTokens.begin();
    map<uint32_t, MptcpTuple>::iterator itEnd = clientTokens.end();
    for (;itBegin != itEnd; itBegin++) {
        uint32_t clientToken = itBegin->first;
        MptcpTuple tuple = itBegin->second;
        uint32_t serverToken = serverTokens[tuple];
        map<uint32_t, vector<MptcpTuple> >::iterator it =
                            countSubConnMap.find(clientToken);
        uint64_t totalData = connDataMap[clientToken];
        uint64_t totalMainConnData = subConnDataMap[tuple];

        vector<MptcpTuple> listConns = it->second;
        cout << "--------- Conn Details ----- " << endl;
        cout << " ipSrc " << tuple.getSrcIp();
        cout << " ipDst " << tuple.getDstIp();
        cout << " srcPort " << tuple.getSrcPort();
        cout << " dstPort " << tuple.getDstPort() << endl;
        cout << " Total data transferred in conn and its subconn " << totalData << endl;
        cout << " Total data transferred in main conn " << totalMainConnData << endl;
        cout << " client Token " << clientToken << endl;
        cout << " server Token " << serverToken << endl << endl;
        cout << " num Sub Connections " << listConns.size() << endl;
        for (int j=0; j < listConns.size(); j++) {
            MptcpTuple subTuple = listConns[j];
            uint64_t totalSubConnData = subConnDataMap[subTuple];
            cout << " Sub Conn " << (j+1) << " Conn Details ipSrc " << subTuple.getSrcIp();
            cout << " ipDst " << subTuple.getDstIp();
            cout << " srcPort " << subTuple.getSrcPort();
            cout << " dstPort " << subTuple.getDstPort() << endl;
            cout << " Total data transferred in sub conn " << totalSubConnData << endl << endl;

        }
        cout << endl << "-----------------------------------" << endl;
    }
}
