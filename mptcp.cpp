/******************************************************************************
 *
 *  File mptcp.cpp
 *  Author: Srinivasan Dwarakanathan
 *  This file processes pcap file specified by the user.
 *  It processes each packet and identifies the mptcp connections,
 *  subconnections. It also gets the client and server tokens used
 *  and it also gets the total data communicated(2-way) on each connection
 *  as well as each sub-connection.
 *
 ******************************************************************************/

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
#include "mptcp_utils.h"




using namespace std;
using namespace mptcp_utils;


/*
 *  Tuple used to match subconn
 */
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



/*
 *  Base class for Crypto Algo used.
 *  This is for future use if different crypto is used.
 */
class CryptoForToken {

    public:
    virtual
    void generateToken (unsigned char * key, int keyLen, unsigned char *out) {
    }

};


/*
 *  SHA1 algorithm is the current crypto used.
 */
class Sha1ForToken: public CryptoForToken {
    public:
    virtual
    void generateToken (unsigned char * key, int keyLen, unsigned char *out) {
        SHA1(key, keyLen, out);
    }

};


/*
 *  The main class for processing packets from pcap file.
 *  It gets the MPTCP connections, subconnections, tokens
 *  and data sent/received.
 */
class ProcessPcap {
    private:
    // map of client token to Main Connection Tuple
    map <uint32_t /*client token*/, MptcpTuple> clientTokens;

    // map of Main connection tuple to serverToken
    map <MptcpTuple, uint32_t /*serverToken */, MptcpTuple> serverTokens;

    // map of main connection tuple to server key
    map <MptcpTuple, vector<unsigned char> /*server key*/, MptcpTuple> keySrcMap;

    // map of token to list of its sub connections
    map <uint32_t /*token */, vector<MptcpTuple>/*list of subconns*/ > countSubConnMap;

    // map of subconn tuple to token
    map <MptcpTuple, uint32_t /*token*/, MptcpTuple > subConnMap;

    // map of token to total connection data
    map <uint32_t/*token*/, uint64_t /*total data in bytes*/> connDataMap;

    // map of subconn tuple to subconn data
    map <MptcpTuple, uint64_t /*data in bytes*/, MptcpTuple> subConnDataMap;

    // Crypto algo to be used.
    CryptoForToken *crypto;

    void processTcpOptions (unsigned char* options, MptcpTuple& tuple,
                    MptcpTuple& revTuple, int isAck,
                    uint64_t dataLength, const unsigned char *tcpHeaderEnd);

    public:
    void processPcapFile (const char * fileName, const char * crypto);
    void printMptcpConnInfo ();

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
    pcap.printMptcpConnInfo ();
}

/*****************************************************************************
 *  processPcapFile
 *  Input: 
 *        fileName -> pcap filename
 *        cryptoName -> crypto algo used only if it is different from 
 *                      the default SHA1.
 *  Output: void
 *  Description: Processes the pcap files. Then it processes each packet.
 *               It specifically collects information about MpTcp Connections.
 ****************************************************************************/
void
ProcessPcap::processPcapFile (const char * fileName, const char * cryptoName) {

    char errBuffer[PCAP_ERRBUF_SIZE];
    pcap_t * pPcap = NULL;
    const unsigned char * readPacket = NULL;
    const unsigned char * packetStart = NULL;
    const unsigned char * headerEnd = NULL;
    const unsigned char * tcpheaderEnd = NULL;
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

        if (readPacket == NULL) {
            cout << " read packet is NULL. Something wrong " << endl;
        }

        // Ethernet frame
        ether_header_t * etherHeader = (ether_header_t*) readPacket;
        int etherType = getEtherType(etherHeader);;
        int etherOffset = 0;

        if (etherType == ETHERTYPE_IPV4) {
            etherOffset = 14;
        } else if (etherType == ETHERTYPE_8021Q) {
            etherOffset = 18;
        } else {
            continue;
        }
        readPacket += etherOffset;
        packetStart = readPacket;

        // IP header
        struct ip *ipHeader =  (struct ip *) readPacket;
        string ipSrc = getSrcIp(ipHeader);
        string ipDst = getDstIp(ipHeader);
        uint64_t totalLength = getTotalFragmentLength(ipHeader);
        int protocol = getProtocol(ipHeader); 
        readPacket = readPacket + sizeof(struct ip);

        if (protocol != TCP_PROTOCOL) {
            continue;
        }

        // TCP Header
        struct tcphdr *tcpHdr = (struct tcphdr *) readPacket;
        unsigned int srcPort = getSrcPort (tcpHdr);
        unsigned int dstPort = getDstPort (tcpHdr);
        unsigned char tcpFlags = getTcpFlags (tcpHdr);
        int isSyn = (tcpFlags & TH_SYN) ? 1 : 0;
        int isAck = (tcpFlags & TH_ACK) ? 1 : 0;

        // tcp header length and total data length
        int tcpHeaderLength = getTcpHeaderLenInBytes (tcpHdr);
        tcpheaderEnd = readPacket + tcpHeaderLength;
        uint64_t headerLength = (uint64_t) tcpheaderEnd - (uint64_t) (packetStart);
        uint64_t dataLength = totalLength - headerLength;

        // When Syn flag is not set
        if (isSyn == 0) {
            MptcpTuple tuple (ipSrc, ipDst, srcPort, dstPort);
            MptcpTuple revTuple (ipDst, ipSrc, dstPort, srcPort);
            uint64_t currentData = 0;
            uint32_t token = 0;
            if (subConnDataMap.find(tuple) != subConnDataMap.end()) {
                currentData = subConnDataMap[tuple];
                subConnDataMap[tuple] = currentData + dataLength;
                token = subConnMap[tuple];
            } else if (subConnDataMap.find(revTuple) != subConnDataMap.end()) {
                currentData = subConnDataMap[revTuple];
                subConnDataMap[revTuple] = currentData + dataLength;
                token = subConnMap[revTuple];
            }
            currentData = 0;
            if (token != 0) {
                currentData = connDataMap[token];
                connDataMap[token] = currentData + dataLength;
            }
        } else if (isSyn != 0) {
            // When SYN flag is set
            countSyns += 1;
            readPacket = readPacket + sizeof(struct tcphdr);
            unsigned char * options = (unsigned char *)readPacket;
            MptcpTuple tuple (ipSrc, ipDst, srcPort, dstPort);
            MptcpTuple revTuple (ipDst, ipSrc, dstPort, srcPort);
            processTcpOptions (options, tuple, revTuple, isAck, dataLength, tcpheaderEnd);
        }
    }

}



/******************************************************************************
 * processTcpOptions
 *
 * Description: Process the MpTcp options in TCP header.
 *
 ******************************************************************************/
void
ProcessPcap::processTcpOptions (unsigned char* options, MptcpTuple& tuple,
                    MptcpTuple& revTuple, int isAck,
                    uint64_t dataLength, const unsigned char* tcpHeaderEnd) {

    unsigned char keySrc[KEY_SIZE_BYTES];
    unsigned char keyDst[KEY_SIZE_BYTES];
    unsigned char sha1[SHA1_OUT_SIZE_BYTES];

    while (1) {
	tcp_options_t * tcpOption = (tcp_options_t *) options;
	if (options >= tcpHeaderEnd) {
	    break;
	}
	if (tcpOption->kind == ENDOF_OPTION_TYPE) {
	    break;
	}
	if (tcpOption->kind == MPTCP_OPTION_TYPE) {
	    mptcp_subtype_version_t *subtypeVersion =
		    (mptcp_subtype_version_t *) (options + 2);
	    if (subtypeVersion->mp_subtype == MP_CAPABLE_SUBTYPE) {
		uint64_t *key = (uint64_t *) (options + 4);
		if (isAck == 0) {
		    memcpy (keySrc, key, KEY_SIZE_BYTES);
		    subConnDataMap[tuple] = dataLength;
		    keySrcMap[tuple] =
                        vector<unsigned char> (keySrc, keySrc + KEY_SIZE_BYTES);
		} else {
		    memcpy (keyDst, key, KEY_SIZE_BYTES);
		    crypto->generateToken(keyDst, KEY_SIZE_BYTES, sha1);
		    uint32_t clientToken = ntohl(*((uint32_t*)sha1));

		    vector <unsigned char> keySource = keySrcMap[revTuple];
		    for (int k=0; k < KEY_SIZE_BYTES; k++) {
			keySrc[k] = keySource[k];
		    }
		    crypto->generateToken(keySrc, KEY_SIZE_BYTES, sha1);
		    uint32_t serverToken = ntohl(*((uint32_t*)sha1));

		    clientTokens[clientToken] = revTuple;
		    serverTokens[revTuple] = serverToken;
		    subConnMap[tuple] = clientToken;
		    subConnMap[revTuple] = clientToken;

		    if (subConnDataMap.find(revTuple) != subConnDataMap.end()) {
			uint64_t currentData = subConnDataMap[revTuple];
			uint64_t connCurrentData = connDataMap[clientToken];
			connDataMap [clientToken] = connCurrentData + currentData + dataLength;
			subConnDataMap [revTuple] = currentData + dataLength;
		    }
		}
	    } else if (subtypeVersion->mp_subtype == MP_JOIN_SUBTYPE &&
		       isAck == 0) {
		unsigned char *key = (unsigned char *) (options + 4);
		uint32_t token = ntohl(*((uint32_t*)key));
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
	    } else if (subtypeVersion->mp_subtype == MP_JOIN_SUBTYPE &&
		       isAck == 1) {
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
	if (tcpOption->kind == NOOP_OPTION_TYPE) {
	    options = ((unsigned char *)options) + 1;
	} else {
	    options = ((unsigned char *)options) + tcpOption->length;
	}
    }
}


/******************************************************************************
 * printMptcpConnInfo
 *
 * Description: Prints the Mptcp Connection and its subconnection informations.
 *
 ******************************************************************************/
void
ProcessPcap::printMptcpConnInfo () {

    map<uint32_t, MptcpTuple>::iterator itBegin = clientTokens.begin();
    map<uint32_t, MptcpTuple>::iterator itEnd = clientTokens.end();
    cout << endl << " Total Number of Distinct Mptcp Connection: " << clientTokens.size() << endl;
    cout << " The details of Connections: " << endl << endl;
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
        cout << " Total data transferred in main conn and its subconns: " << totalData << " bytes" << endl;
        cout << " Total data transferred in main conn: " << totalMainConnData << " bytes" << endl;
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
            cout << " Total data transferred in sub conn: " << totalSubConnData << " bytes" << endl << endl;

        }
        cout << endl << "-----------------------------------" << endl;
    }
}
