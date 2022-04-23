# diff-serv-code-point
Using DSCP (Diff-Serv Code Point) in UDP traffic for the low-latency (expidite) forwarding of realtime audio/video traffic.

Differentiated services or DiffServ is a computer networking architecture that specifies a simple and scalable mechanism for classifying and managing network traffic and providing quality of service (QoS) on modern IP networks. DiffServ can, for example, be used to provide low-latency to critical network traffic such as voice or streaming media while providing simple best-effort service to non-critical services such as web traffic or file transfers.

Please see https://datatracker.ietf.org/doc/html/rfc2474 for the detail.

This repository contains a C++ example in which a DSCP value is set for the transmitted UDP packets. The server side receiving the packet gets the incoming DSCP value in the IP header. 

DSCP value used in this example is (0x2E << 2 = 0xB8). DSCP use the top most significant bits of TOS byte in the IPV4 header. DSCP value of 0xB8 means that a particular UDP packet will be considered as a critical network traffic by the layer 3 routers and switches between the source and destination endpoint. 0xB8 is usually used in Audio/Video realtime traffic.
