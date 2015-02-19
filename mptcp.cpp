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
#include <sstream>
#include <string>
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
    uint64_t index;
    string compareAll;
    string compareTuple;

    public:
    MptcpTuple () {
    }

    MptcpTuple (string sIp, string dIp, int sPort, int dPort):
        srcIp(sIp), dstIp(dIp), srcPort(sPort), dstPort(dPort) {
         stringstream ss;
         ss << srcIp << srcPort << dstIp << dstPort;
         compareTuple = ss.str();
    }

    MptcpTuple (string sIp, string dIp, int sPort, int dPort, uint64_t idx):
        srcIp(sIp), dstIp(dIp), srcPort(sPort), dstPort(dPort), index(idx) {
         stringstream ss;
         ss << srcIp << srcPort << dstIp << dstPort;
         compareTuple = ss.str();
         ss << index;
         compareAll = ss.str();
    }

    bool operator () (const MptcpTuple &lhs, const MptcpTuple &rhs) const {
        return (lhs.compareAll.compare(rhs.compareAll) < 0);
    }

    bool compareJustTuple (const MptcpTuple &rhs) const {
        return (compareTuple.compare(rhs.compareTuple) < 0);
    }

    void setIndex (uint64_t idx) {
        stringstream ss;
        ss << compareTuple;
        index = idx;
        ss << index;
        compareAll = ss.str();
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


class CompareJustTuple {
    public:
    bool operator () (const MptcpTuple &lhs, const MptcpTuple &rhs) {
        return (lhs.compareJustTuple (rhs));
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
    void generateHmacMessage (unsigned char * key, int keyLen,
            unsigned char *data, int dataLen,
            unsigned char * out, unsigned int*len) {
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

    void generateHmacMessage (unsigned char * key, int keyLen,
                              unsigned char *data, int dataLen,
                              unsigned char *out, unsigned int *len) {
    }
};



/*
 *  Enum to maintain connection states.
 */
typedef enum {
    SYN_CAPABLE_STATE = 0,
    SYN_ACK_CAPABLE_STATE,
    SYN_JOIN_STATE,
    SYN_ACK_JOIN_STATE,
    CONNECTED_STATE,
    STATE_MAX

} connection_state_t;


/*
 *  Enum to maintain ack msg type.
 */
typedef enum {
    CAPABLE_ACK_TYPE = 0,
    JOIN_ACK_TYPE,
    MAX_ACK_TYPE
} ack_msg_type_t;

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

    // map of main connection tuple to sender key
    map <MptcpTuple, vector<unsigned char> /*server key*/, MptcpTuple> keySrcMap;

    // map of main connection tuple to receiver key
    map <MptcpTuple, vector<unsigned char> /*server key*/, MptcpTuple> keyDstMap;

    // map of main connection tuple to randon mumber
    map <MptcpTuple, uint32_t /*random Number*/, MptcpTuple> senderRandomMap;

    // map of main connection tuple to randon mumber
    map <MptcpTuple, uint32_t /*random Number*/, MptcpTuple> receiverRandomMap;

    // map of token to list of its sub connections
    map <uint32_t /*token */, vector<MptcpTuple>/*list of subconns*/ > countSubConnMap;

    // map of subconn tuple to token
    map <MptcpTuple, uint32_t /*token*/, MptcpTuple > subConnMap;

    // map of token to total connection data
    map <uint32_t/*token*/, uint64_t /*total data in bytes*/> connDataMap;

    // map of subconn tuple to subconn data
    map <MptcpTuple, uint64_t /*data in bytes*/, MptcpTuple> subConnDataMap;

    // map of tuple to connection state
    map <MptcpTuple, connection_state_t, MptcpTuple> connectionState;


    // map of tuple to tuple index
    map <MptcpTuple, uint64_t, CompareJustTuple> indexMap;


    // Crypto algo to be used.
    CryptoForToken *crypto;

    void setConnectionState (connection_state_t state, MptcpTuple& tuple) {
        connectionState[tuple] = state;
    }

    connection_state_t getConnectionState (MptcpTuple& tuple) {
        if (connectionState.find(tuple) != connectionState.end()) {
            return connectionState[tuple];
        }
        return STATE_MAX;
    }

    connection_state_t getConnectionState (uint32_t token) {
        MptcpTuple tuple = clientTokens[token];
        if (connectionState.find(tuple) != connectionState.end()) {
            return connectionState[tuple];
        }
        return STATE_MAX;
    }

    bool verifyHmacFlag (mptcp_subtype_version_t* subtypeVersion) {
       return isMptcpHflagSet(subtypeVersion);
    }

    void getSrcKey (unsigned char * keySrc, uint32_t token) {
        MptcpTuple tuple = clientTokens[token];
        vector <unsigned char> keySource = keySrcMap[tuple];
        for (int k=0; k < KEY_SIZE_BYTES; k++) {
	    keySrc[k] = keySource[k];
	}
    }

    void getDstKey (unsigned char * keyDst, uint32_t token) {
        MptcpTuple tuple = clientTokens[token];
        vector <unsigned char> key = keyDstMap[tuple];
        for (int k=0; k < KEY_SIZE_BYTES; k++) {
	    keyDst[k] = key[k];
	}
    }

    void getHmacKey (unsigned char * keySrc, unsigned char * keyDst,
                     unsigned char * hmacKey) {
        memcpy (hmacKey, keySrc, KEY_SIZE_BYTES);
        memcpy (hmacKey + KEY_SIZE_BYTES, keyDst, KEY_SIZE_BYTES);
    }
    void getHmacData (uint32_t sender, uint32_t receiver,
                      unsigned char * hmacData) {
        memcpy (hmacData, (unsigned char *)&sender, 4);
        memcpy (hmacData + 4, (unsigned char *)&receiver, 4);
    }

    void setTupleWithIndex (MptcpTuple& tuple, MptcpTuple& revTuple) {
        if (indexMap.find(tuple) != indexMap.end()) {
            tuple.setIndex(indexMap[tuple]);
        }
        if (indexMap.find(revTuple) != indexMap.end()){
            revTuple.setIndex(indexMap[tuple]);
        }
    }

    void updateConnectionData (uint32_t token, uint64_t dataLength) {
        uint64_t currentData = 0;
        if (token != 0) {
            if (connDataMap.find(token) != connDataMap.end()) {
                currentData = connDataMap[token];
            }
            connDataMap[token] = currentData + dataLength;
        }
    }


    bool verifyKeysInAck (uint32_t token,
            unsigned char * options, unsigned char * tcpheaderEnd);

    bool verifyHmacInAck (uint32_t token, MptcpTuple& tuple,
           unsigned char * options, unsigned char * tcpheaderEnd);

    void getFullHmac (uint32_t token, MptcpTuple& tuple, vector<uint32_t>& hMsg);

    uint64_t getTruncatedHmac (uint32_t token, MptcpTuple& tuple);

    void processTcpOptions (unsigned char* options, MptcpTuple& tuple,
                    MptcpTuple& revTuple, int isAck, uint64_t index,
                    uint64_t dataLength, const unsigned char *tcpHeaderEnd);

    bool extractFromMptcpOption (ack_msg_type_t type, unsigned char* options,
        unsigned char * tcpHeaderEnd, vector<uint32_t>& hmacMessage,
        vector<uint64_t>& option64Bits);

    public:
    void processPcapFile (const char * fileName, const char * crypto);

    void printMptcpConnInfo ();

};



/*****************************************************************************
 *  verifyKeysInAck
 *  Description: verifies that keys in Ack matches with the ones associated
 *               with the sub-flow.
 *
 ****************************************************************************/
bool
ProcessPcap::verifyKeysInAck (uint32_t token,
        unsigned char * options, unsigned char * tcpheaderEnd) {
    vector<uint64_t> keysVec;
    vector<uint32_t> dummy;

    if (extractFromMptcpOption (CAPABLE_ACK_TYPE, options, tcpheaderEnd,
                                    dummy, keysVec) == false) {
        return false;
    }
    unsigned char keySrc[KEY_SIZE_BYTES];
    unsigned char keyDst[KEY_SIZE_BYTES];
    getSrcKey (keySrc, token);
    getDstKey (keyDst, token);

    uint64_t sourceKey = be64toh(*((uint64_t*) keySrc));
    uint64_t dstKey = be64toh(*((uint64_t*) keyDst));

    if (sourceKey != keysVec[0] || dstKey != keysVec[1]) {
        return false;
    }
    return true;
}


/*****************************************************************************
 *  verifyHmacInAck
 *  Description: Compares the Hmac in the ack message with the computed hmac
 *               and returns false if there is amismatch.
 *
 ****************************************************************************/
bool
ProcessPcap::verifyHmacInAck (uint32_t token, MptcpTuple& tuple,
        unsigned char * options, unsigned char * tcpheaderEnd) {
    vector<uint32_t> computedHmac;
    vector<uint32_t> ackMsgHmac;
    vector<uint64_t> dummy;
    if (extractFromMptcpOption (JOIN_ACK_TYPE, options, tcpheaderEnd,
                            ackMsgHmac, dummy) == false) {
        return false;
    }
    getFullHmac (token, tuple, computedHmac);

    int numWords = SHA1_OUT_SIZE_BYTES / 4;
    for (int i = 0; i < numWords; i++) {
        if (computedHmac[i] != ackMsgHmac[i]) {
            return false;
        }
    }
    return true;
}


/*****************************************************************************
 *  getTruncatedHmac
 *  Description: gets the truncated 64 bit Hmac by computing from the keys
 *               and random number associated with the sub-flow.
 *
 ****************************************************************************/
uint64_t 
ProcessPcap::getTruncatedHmac (uint32_t token, MptcpTuple& tuple) {
    unsigned char keySrc[KEY_SIZE_BYTES];
    unsigned char keyDst[KEY_SIZE_BYTES];
    unsigned char hmacKey[2 * KEY_SIZE_BYTES];
    unsigned char hmacData[KEY_SIZE_BYTES];
    unsigned char hmacResult[20] = {0};
    unsigned int md_len = 20;

    getSrcKey (keySrc, token);
    getDstKey (keyDst, token);
    getHmacKey (keyDst, keySrc, hmacKey);
    uint32_t senderR = senderRandomMap[tuple];
    uint32_t receiverR = receiverRandomMap[tuple];
    getHmacData (receiverR, senderR, hmacData);

    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init(&ctx, hmacKey, sizeof(hmacKey), EVP_sha1());
    HMAC_Update(&ctx, hmacData, sizeof(hmacData));
    HMAC_Final(&ctx, hmacResult, &md_len);
    HMAC_CTX_cleanup(&ctx);

    uint64_t truncatedHmac = be64toh (*((uint64_t*) (hmacResult)));
    return truncatedHmac;
}


/*****************************************************************************
 *  getFullHmac
 *  Description: gets the Full 160 bit Hmac by computing from the keys
 *               and random number associated with the sub-flow.
 *
 ****************************************************************************/
void
ProcessPcap::getFullHmac (uint32_t token, MptcpTuple& tuple, vector<uint32_t>& hMsg) {
    unsigned char keySrc[KEY_SIZE_BYTES];
    unsigned char keyDst[KEY_SIZE_BYTES];
    unsigned char hmacKey[2 * KEY_SIZE_BYTES];
    unsigned char hmacData[KEY_SIZE_BYTES];
    unsigned char hmacResult[SHA1_OUT_SIZE_BYTES];
    unsigned int md_len = SHA1_OUT_SIZE_BYTES;

    getSrcKey (keySrc, token);
    getDstKey (keyDst, token);
    getHmacKey (keySrc, keyDst, hmacKey);
    uint32_t senderR = senderRandomMap[tuple];
    uint32_t receiverR = receiverRandomMap[tuple];
    getHmacData (senderR, receiverR, hmacData);

    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init(&ctx, hmacKey, sizeof(hmacKey), EVP_sha1());
    HMAC_Update(&ctx, hmacData, sizeof(hmacData));
    HMAC_Final(&ctx, hmacResult, &md_len);
    HMAC_CTX_cleanup(&ctx);

    int wordSize = 4;
    for (int i =0; i < SHA1_OUT_SIZE_BYTES; i += wordSize) {
        uint32_t hmac = ntohl(*((uint32_t*) (hmacResult + i)));
        hMsg.push_back(hmac);
    }
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
    uint64_t i = 0;
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
        uint64_t packetIndex = i;

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
            setTupleWithIndex (tuple, revTuple);
            uint64_t currentData = 0;
            uint32_t token = 0;

            unsigned char * options =
                   (unsigned char *) readPacket + sizeof(struct tcphdr);
            if (getConnectionState (tuple) == SYN_ACK_CAPABLE_STATE) {
                token = subConnMap[tuple];
                if (verifyKeysInAck (token,
                        options, (unsigned char *)tcpheaderEnd)) {
                    setConnectionState(CONNECTED_STATE, tuple);
                } else {
                    continue;
                }
            }
            if (getConnectionState (tuple) == SYN_ACK_JOIN_STATE) {
                token = subConnMap[tuple];
                if (verifyHmacInAck (token, tuple,
                        options, (unsigned char *)tcpheaderEnd)) {
                    setConnectionState(CONNECTED_STATE, tuple);
                } else {
                    continue;
                }
            }


            if (getConnectionState (tuple) != CONNECTED_STATE &&
                getConnectionState(revTuple) != CONNECTED_STATE) {
                continue;
            }
 
            if (subConnDataMap.find(tuple) != subConnDataMap.end()) {
                currentData = subConnDataMap[tuple];
                subConnDataMap[tuple] = currentData + dataLength;
                token = subConnMap[tuple];
            } else if (subConnDataMap.find(revTuple) != subConnDataMap.end()) {
                currentData = subConnDataMap[revTuple];
                subConnDataMap[revTuple] = currentData + dataLength;
                token = subConnMap[revTuple];
            }
            updateConnectionData (token, dataLength);
        } else if (isSyn != 0) {
            // When SYN flag is set
            countSyns += 1;
            readPacket = readPacket + sizeof(struct tcphdr);
            unsigned char * options = (unsigned char *)readPacket;
            MptcpTuple tuple (ipSrc, ipDst, srcPort, dstPort);
            MptcpTuple revTuple (ipDst, ipSrc, dstPort, srcPort);
            processTcpOptions (options, tuple, revTuple, isAck, packetIndex,
                               dataLength, tcpheaderEnd);
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
                    MptcpTuple& revTuple, int isAck, uint64_t packetIndex,
                    uint64_t dataLength, const unsigned char* tcpHeaderEnd) {

    unsigned char keySrc[KEY_SIZE_BYTES];
    unsigned char keyDst[KEY_SIZE_BYTES];
    unsigned char sha1[SHA1_OUT_SIZE_BYTES];
    unsigned char hmacKey[2 * KEY_SIZE_BYTES];
    unsigned char hmacData[KEY_SIZE_BYTES];

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
                if (verifyHmacFlag(subtypeVersion) == false) {
                    // H Flag not set. so normal TCP.
                    break;
                }
		uint64_t *key = (uint64_t *) (options + 4);
		if (isAck == 0) {
		    memcpy (keySrc, key, KEY_SIZE_BYTES);
                    indexMap[tuple] = packetIndex;
                    indexMap[revTuple] = packetIndex;
                    setTupleWithIndex (tuple, revTuple);
		    subConnDataMap[tuple] = dataLength;
		    keySrcMap[tuple] =
                        vector<unsigned char> (keySrc, keySrc + KEY_SIZE_BYTES);
                    setConnectionState (SYN_CAPABLE_STATE, tuple);
		} else {
                    setTupleWithIndex (tuple, revTuple);
		    memcpy (keyDst, key, KEY_SIZE_BYTES);
		    keyDstMap[revTuple] =
                        vector<unsigned char> (keyDst, keyDst + KEY_SIZE_BYTES);
		    crypto->generateToken(keyDst, KEY_SIZE_BYTES, sha1);
		    uint32_t clientToken = ntohl(*((uint32_t*)sha1));

		    clientTokens[clientToken] = revTuple;
                    getSrcKey(keySrc, clientToken);
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
                    setConnectionState (SYN_ACK_CAPABLE_STATE, revTuple);
		}
	    } else if (subtypeVersion->mp_subtype == MP_JOIN_SUBTYPE &&
		       isAck == 0) {
		unsigned char *key = (unsigned char *) (options + 4);
		uint32_t token = ntohl(*((uint32_t*)key));
                bool useReverse = true;
                if (clientTokens.find(token) == clientTokens.end() ||
                    (clientTokens.find(token) != clientTokens.end() &&
                     getConnectionState (token) != CONNECTED_STATE)) {
                    // token Invalid or the main connection
                    // is not in connected state.
                    break;
                }
                indexMap[tuple] = packetIndex;
                indexMap[revTuple] = packetIndex;
                setTupleWithIndex (tuple, revTuple);
		unsigned char *random = (unsigned char *) (options + 8);
		uint32_t randomNum = *((uint32_t*)random);
                senderRandomMap[tuple] = randomNum;

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

                updateConnectionData (token, dataLength);

                setConnectionState (SYN_JOIN_STATE, tuple);
	    } else if (subtypeVersion->mp_subtype == MP_JOIN_SUBTYPE &&
		       isAck == 1) {
                setTupleWithIndex (tuple, revTuple);
		uint64_t currentData = 0;
		uint32_t token = subConnMap[revTuple];
		unsigned char *hmac = (unsigned char *) (options + 4);
		uint64_t truncHmac = be64toh (*((uint64_t*)hmac));
		unsigned char *random = (unsigned char *) (options + 12);
		uint32_t randomNum = *((uint32_t*)random);
                receiverRandomMap[revTuple] = randomNum;

                uint64_t generatedHmac = getTruncatedHmac (token, revTuple);
                vector<uint32_t> hmacMsg;
                getFullHmac (token, revTuple,hmacMsg);
                if (truncHmac != generatedHmac) {
                    break;
                }

                updateConnectionData (token, dataLength);

		currentData = 0;
		if (subConnDataMap.find(revTuple) != subConnDataMap.end()) {
		    currentData = subConnDataMap[revTuple];
		    subConnDataMap [revTuple] = currentData + dataLength;
		}
                setConnectionState (SYN_ACK_JOIN_STATE, revTuple);
	    }
	}
	if (tcpOption->kind == NOOP_OPTION_TYPE) {
	    options = ((unsigned char *)options) + 1;
	} else {
	    options = ((unsigned char *)options) + tcpOption->length;
	}
    }
}


bool
ProcessPcap::extractFromMptcpOption (ack_msg_type_t type, unsigned char* options,
    unsigned char * tcpHeaderEnd, vector<uint32_t>& hmacMessage,
    vector<uint64_t>& option64Bit) {

    while (1) {
	tcp_options_t * tcpOption = (tcp_options_t *) options;
	if (options >= tcpHeaderEnd) {
	    break;
	}
	if (tcpOption->kind == ENDOF_OPTION_TYPE) {
	    break;
	}
	if (tcpOption->kind == MPTCP_OPTION_TYPE) {
            if (type == JOIN_ACK_TYPE) {
                if (tcpOption->length != 24) {
                    return false;
                }
                for (int i = 0; i < 5; i++) {
                    unsigned char *hmac = (unsigned char *) (options + 4 + i*4);
		    uint32_t num = ntohl(*((uint32_t*)hmac));
                    hmacMessage.push_back (num);
                }
                return true;
            }
            if (type == CAPABLE_ACK_TYPE) {
                if (tcpOption->length != 20) {
                    return false;
                }
                for (int i = 0; i < 2; i++) {
                    unsigned char *key = (unsigned char *) (options + 4 + i*8);
		    uint64_t num = be64toh(*((uint64_t*)key));
                    option64Bit.push_back (num);
                }
                return true;
            }
        }
	if (tcpOption->kind == NOOP_OPTION_TYPE) {
	    options = ((unsigned char *)options) + 1;
	} else {
	    options = ((unsigned char *)options) + tcpOption->length;
	}
    }
    return false;
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
    cout << endl << " The details of Connections: " << endl << endl;
    int validMptcpConnections = 0;

    for (;itBegin != itEnd; itBegin++) {
        uint32_t clientToken = itBegin->first;
        MptcpTuple tuple = itBegin->second;
        if (getConnectionState(tuple) != CONNECTED_STATE) {
            continue;
        }
        validMptcpConnections += 1;
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
            if (getConnectionState(subTuple) != CONNECTED_STATE) {
                continue;
            }
            uint64_t totalSubConnData = subConnDataMap[subTuple];
            cout << " Sub Conn " << (j+1) << " Conn Details ipSrc " << subTuple.getSrcIp();
            cout << " ipDst " << subTuple.getDstIp();
            cout << " srcPort " << subTuple.getSrcPort();
            cout << " dstPort " << subTuple.getDstPort() << endl;
            cout << " Total data transferred in sub conn: " << totalSubConnData << " bytes" << endl << endl;

        }
        cout << endl << "-----------------------------------" << endl;
    }
    cout << endl << " Total Number of Distinct Mptcp Connections : " << validMptcpConnections << endl << endl;
}



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
