#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <cstring>
#include <linux/net_tstamp.h>


/*
* Gets the ancillary data from the received message.
* @param msg input message
* @param level level of the ancillery data.
* @param type type of the ancillery data.
*/
inline int *get_ancillary_data(msghdr &msg, int level, int type)
{
    for (cmsghdr *cmptr = CMSG_FIRSTHDR(&msg); cmptr != NULL; cmptr = CMSG_NXTHDR(&msg, cmptr))
    {
        if (cmptr->cmsg_level == level && cmptr->cmsg_type == type)
        {
            return (int *)CMSG_DATA(cmptr);
        }
    }

    return nullptr;
}

/*
 * Function to send test udp packet to remote ip/port.
 */
int send_test_udp_packet(const uint8_t total_udp_packets, const std::string local_ip, const uint16_t local_port, const std::string remote_ip, const uint16_t remote_port)
{
    std::cout << "UDP packet sender start ... " << std::endl;

    sockaddr_in remote_addr;
    bzero((char *)&remote_addr, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(remote_port);

    if (inet_pton(AF_INET, remote_ip.c_str(), &remote_addr.sin_addr) <= 0)
    {
        std::cerr << "Unable to convert ip address to binary form. IP address: " << remote_ip.c_str() << std::endl;
        return -1;
    }

    // Creating socket.
    sockaddr_in local_addr;
    bzero((char *)&local_addr, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = htons(local_port);

    int sock_fd = socket(AF_INET, (SOCK_DGRAM | SOCK_NONBLOCK), 0);
    if (sock_fd < 0)
    {
        std::cout << "Unable to create test session socket. Errno: " << std::strerror(errno) << std::endl;
        return -1;
    }

    // Set socket option to reuse port (otherwise might have to wait 4 minutes every time socket is closed).
    int option = 1;
    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0)
    {
        std::cout << "Unable to set SO_REUSEADDR option on socket. Errno: " << std::strerror(errno) << std::endl;
        close(sock_fd);
        return -1;
    }

    // Bind the socket to local address.
    int bind_status = bind(sock_fd, (struct sockaddr *)&local_addr, sizeof(local_addr));
    if (bind_status < 0)
    {
        std::cout << "Unable to bind socket. Errno: " << std::strerror(errno) << std::endl;
        close(sock_fd);
        return -1;
    }

    // Creating message to send.
    char msg[50]{};
    iovec snd_iov[0];
    snd_iov[0].iov_base = msg;
    snd_iov[0].iov_len = sizeof(msg);

    // Creating an ancillery data buffer, wrapped in a union in order to ensure it is suitably aligned.
    // This will contain any control information to be sent from user space. In our case, we will be passing
    // a DSCP value which will be set into the IP header by networking stack.
    union
    {
        char buf[CMSG_SPACE(1)];
        struct cmsghdr align;
    } u;

    msghdr snd_msg;
    snd_msg.msg_name = &remote_addr;
    snd_msg.msg_namelen = sizeof(remote_addr);
    snd_msg.msg_iov = snd_iov;
    snd_msg.msg_iovlen = 1;
    snd_msg.msg_control = u.buf;                    //Setting ancillery data buffer pointer to msg_control.
    snd_msg.msg_controllen = sizeof(u.buf);         //Setting ancillery data buffer length.

    //Setting values in control message.
    cmsghdr *cmsg = CMSG_FIRSTHDR(&snd_msg);
    cmsg->cmsg_level = IPPROTO_IP;
    cmsg->cmsg_type = IP_TOS;                       //Setting message type to TOS (DSCP).
    cmsg->cmsg_len = CMSG_LEN(1);                   //Control message length is one.
    const unsigned char dscp = (0x2E << 2);         //DSCP use top most significant bits of TOS bytes. That's why shifting it left by two bits.
    memcpy(CMSG_DATA(cmsg), &dscp, sizeof(dscp));   //Setting the DSCP value 0x2E = 46 (Expidite forwarding)

    // Sending message.
    for (int i = 0; i < total_udp_packets; i++)
    {
        int data_sent = sendmsg(sock_fd, &snd_msg, 0);
        if (data_sent <= 0)
        {
            std::cerr << "Unable to send udp packet. " << std::endl;
        }

        usleep(100000);
    }

    std::cout << "UDP packet sender end ... " << std::endl;
    close(sock_fd);
    return 0;
}

int receive_test_udp_packets(const uint16_t local_port)
{
    // Creating socket.
    sockaddr_in local_addr;
    bzero((char *)&local_addr, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = htons(local_port);

    int sock_fd = socket(AF_INET, (SOCK_DGRAM | SOCK_NONBLOCK), 0);
    if (sock_fd < 0)
    {
        std::cout << "Unable to create test session socket. Errno: " << std::strerror(errno) << std::endl;
        return -1;
    }

    // Set socket option to reuse port (otherwise might have to wait 4 minutes every time socket is closed).
    int option = 1;
    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0)
    {
        std::cout << "Unable to set SO_REUSEADDR option on socket. Errno: " << std::strerror(errno) << std::endl;
        close(sock_fd);
        return -1;
    }

    // Set socket option to receive TOS (DSCP) byte from IP header.
    // The TOS (DSCP) information will be delivered to user space via control messages (ancillery data) by calling recvmsg api.
    option = 1;
    if (setsockopt(sock_fd, IPPROTO_IP, IP_RECVTOS, &option, sizeof(option)) < 0)
    {        
        std::cout << "Unable to set IP_RECVTOS option on socket. Errno: " << std::strerror(errno) << std::endl;
        close(sock_fd);
        return -1;
    }

    // Bind the socket to local address.
    int bind_status = bind(sock_fd, (struct sockaddr *)&local_addr, sizeof(local_addr));
    if (bind_status < 0)
    {
        std::cout << "Unable to bind socket. Errno: " << std::strerror(errno) << std::endl;
        close(sock_fd);
        return -1;
    }

    // Creating message to receive.
    char buff[200]{};
    sockaddr_in remote_addr;
    char control_msg[8192]{};

    iovec rcv_iov[1];
    rcv_iov[0].iov_base = buff;
    rcv_iov[0].iov_len = sizeof(buff);

    msghdr rcv_msg;
    rcv_msg.msg_name = &remote_addr;
    rcv_msg.msg_namelen = sizeof(remote_addr);
    rcv_msg.msg_iov = rcv_iov;
    rcv_msg.msg_iovlen = 1;
    rcv_msg.msg_control = control_msg;
    rcv_msg.msg_controllen = sizeof(control_msg);

    std::cout << "Listening for UDP packets on port: " << local_port << std::endl;

    while (true)
    {
        int recv_data_len = recvmsg(sock_fd, &rcv_msg, 0);
        if (recv_data_len == 0)
        {
            usleep(50);
            continue;
        }
        else if (recv_data_len < 0)
        {
            if (errno != EAGAIN && errno != EWOULDBLOCK) // As the socket is non-blocking so EAGAIN or EWOULDBLOCK means that there is no data available. Wait for some time and try again.
            {
                std::cout << "Unable to read data from socket. Errno: %s" << std::strerror(errno) << std::endl;
            }
            usleep(50);
            continue;
        }

        // Message is received. Getting the received TOS (DSCP) value from received message control data.
        int *ptr = get_ancillary_data(rcv_msg, IPPROTO_IP, IP_TOS);
        if (ptr)
        {
            unsigned char dscp = *ptr;
            std::cout << "DSCP received: " << std::hex << (int)dscp << std::endl;
        }
        else
        {
            std::cerr << "No DSCP received. " << std::endl;
        }
    }
}


/*
* Main function 
*/
int main(int argc, char *argv[])
{
    if (argc == 2 && strcmp(argv[1], "-s") == 0)
    {
        //Sending test packets.
        send_test_udp_packet(10, "127.0.0.1", 7400, "127.0.0.1", 8000);
    }
    else if (argc == 2 && strcmp(argv[1], "-r") == 0)
    {
        //Receiving test packets.
        receive_test_udp_packets(8000);
    }
    else
    {
        std::cout << "Invalid arguments. Usage: " << std::endl;
        std::cout << "./test -s (to run as udp packet sender)" << std::endl;
        std::cout << "./test -r (to run as udp packet receiver)" << std::endl;
    }

    return 0;
}