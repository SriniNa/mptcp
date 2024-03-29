# mptcp

Project for mptcp experiments.

Installing required libraries:
sudo apt-get install libpcap-dev
sudo apt-get install libssl-dev

Compilation of code:
g++ mptcp.cpp -lpcap -lssl -lcrypto 

Running Code:
./a.out pcapFileName


FILES:
mptcp.cpp : The code for Task1 and Task2.
mptcp_utils.h: The utils functions and #defines.

Not used files:
mptcp.c: Was created initially before switching to cpp.
test-hmac.c: used to test hmac-sha1 and sha1.


For Task1, had to compute the clienToken after exchange of keys from client and servers.
The Crypto algorithm used is SHA1.
The code has a separate class CryptoForToken with a virtual method to generate token.
Sha1ForToken derives from CryptoForToken. In future as mentioned in RFC6284, if more
support is added for other cypto algorithms, then new derived classes can be added.
The token is computed when the MpTcp connection is added with TCP options MPTCP
and subtype MP_CAPABLE. When subconnections are added, the connection is identified by 
the token specified in the Join. The client and server tokens' decimal value is printed
in the program output.

For task2, from the IP header, total IP fragment length is got. TCP header has the
total TCP header in bytes. So, using the above two information, total data length
is computed. If it is a MpTcp packet, then the dataLength is added to the connection's
total data communicated value. Subconnections are identified by their tuples. There is
a map which stores the mapping between tuple and the connection token. This info is used
to identify the connection.
