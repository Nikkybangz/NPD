# NPD
Network Protocol Design
                               ITC8060 - NETWORK PROTOCOL DESIGN ASSIGNMENT
                                    SUPERVISOR: Prof. Olaf Mannuel
                                        GROUP MEMBERS:
                                    Anita Nwaokolo – 184692ICVM
                                      Henry Dola – 184518IVCM
                                Jayavarshini Thirumalai 184508IVCM
                                
                                
Ideas:
One-to-one communication
One-to-all communication
Transfer Messages and files

OBJECTIVE
To create an application that runs over the UDP connection and enables the users to transfer messages as well as files.
SOFTWARES USED:
Python 3.7
Windows and Linux

DESCRIPTION:
Routers are independent of each other router and so interface has to be created between the routers to communicate with each other. To perform this, the sockets are required which allows routers running in different machines and would still be able to communicate. At a specified port, the router interface is implemented as a listening socket.
To develop a UDP application that allows the users to chat and send files can be accomplished with the help of sockets. In Python, socket packages comes in-built and it can be simply imported. Threading is also required to handle multiple users for sending the messages and it comes with pre-installed.
In order to avoid the formation of loops, we can initiate such as time-to-live and the shortest path to destination. In this protocol, the routing of packets from source to destination was accomplished by identifying the shortest path from the routing table using Bellman-Ford Algorithm. This is a single source vertex to all other vertices in a weighted graph and it is useful in handling the negative cycles.
“This is a brief report for the Network Protocol Design submitted to Professor Olaf on 13th of June 2019”.
The protocol design Requirements is as follows:
• UDP
• Datagram max len 100 bytes
• Routed
Identity: Generating GPG key
Message struct: https://gitlab.cs.ttu.ee/taroja/itc8061
Representing data:
• Binary
• Metadata
• display strings UTF-8
Routing (type 0b0xx)
• request full tables
• send full table
• update route

REFERENCES:
https://ois.ttu.ee/ois2/docs/HKRIT.111250/ITC8061-eng.pdf
https://code.tutsplus.com/tutorials/introduction-to-network-programming-in-python--cms-30459
https://github.com/baudm/ospf-sim - for routing process
