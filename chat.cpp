#include <iostream>
#include <string>
#include <sys/socket.h>
#include <sys/select.h>
#include <thread>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <cstring> // for memset
#include <fcntl.h>

#define BUFFER_SIZE 1024
#define DISCOVERY_PORT 9000
#define DISCOVERY_MESSAGE "Peer discovery broadcast"
using namespace std;

// function prototypes/declarations
int initialize_tcp_listener(const std::string &local_ip, int &tcp_port);
// void broadcast_presence(const std::string &local_ip, int tcp_port);
void broadcast_presence(const std::string &local_ip, int tcp_port, std::string local_name);
// std::pair<std::string, int> discover_peers(const std::string &local_ip,int tcp_port);
std::tuple<std::string, std::string, int> discover_peers(const std::string &local_name, const std::string &local_ip, int tcp_port);

bool establish_connection(int &connection_sock, int listening_sock, const std::string &peer_ip, int peer_port);
// void enable_non_blocking_io(int connection_sock);
void handle_chat_session(int connection_sock, const std::string &local_name);
std::string get_local_ip();

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <peer_name>" << std::endl;
        return 1;
    }
    // listening_sock is for waiting for incoming connections.
    // connection_sock is for the actual communication.

    std::string local_name = argv[1]; // Get the peer's name from the command-line argument
    std::string local_ip = get_local_ip();
    // Dynamically assign a TCP port for communication
    int tcp_port;
    int listening_sock = initialize_tcp_listener("0.0.0.0", tcp_port); // Listen on a random TCP port

    // Start broadcasting presence with the dynamically assigned TCP port and local ip
    std::thread broadcaster(broadcast_presence, local_ip, tcp_port, local_name);

    // Listen for peer discovery and connect using the discovered IP and TCP port

    std::cout << "Discovering peers..." << std::endl;
     auto peer_info = discover_peers(local_name, local_ip, tcp_port); // extracting the ip and port of peer
    //let us unpack the tuple
    std::string peer_name = std::get<0>(peer_info);
    std::string peer_ip = std::get<1>(peer_info);
    int peer_port = std::get<2>(peer_info);
    std::cout << "Discovered peer details: " << std::get<0>(peer_info) << ", " << std::get<1>(peer_info) << ", " << std::get<2>(peer_info) << std::endl;
   

    // std::string peer_ip=peer_info.first;
    // int peer_port = peer_info.second;
    // connected is the flag to track whether we are connected

    int connection_sock = listening_sock; // default is listening mode
    bool connected = establish_connection(connection_sock, listening_sock, peer_ip, peer_port);

    if (connected)
    {
        // enable_non_blocking_io(connection_sock);
        handle_chat_session(connection_sock, local_name); // Pass the peer's name to the chat loop
    }
    else
    {
    std:
        cerr << "Failed to establish a connection.Exiting now , try again later." << std::endl;
    }

    broadcaster.detach(); // Keep broadcasting running in the background
    return 0;
}

int initialize_tcp_listener(const std::string &local_ip, int &tcp_port)
{
    // Step 1: Create a TCP socket
    int tcp_sock = socket(AF_INET, SOCK_STREAM, 0); // AF_INET = IPv4, SOCK_STREAM = TCP
    if (tcp_sock == -1)
    {
        std::cerr << "Error: Failed to create TCP socket." << std::endl;
        return -1; // Return error if socket creation failed
    }

    // Step 2: Set up the socket address structure
    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(tcp_port);                      // Convert port to network byte order
    inet_pton(AF_INET, local_ip.c_str(), &server_addr.sin_addr); // Convert IP to binary form

    // Step 3: Bind the socket to the IP and port
    if (bind(tcp_sock, (sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        std::cerr << "Error: Failed to bind TCP socket to " << local_ip << ":" << tcp_port << std::endl;
        close(tcp_sock);
        return -1; // Return error if binding failed
    }

    if (tcp_port == 0)
    {
        socklen_t addr_len = sizeof(server_addr);
        if (getsockname(tcp_sock, (sockaddr *)&server_addr, &addr_len) == -1)
        {
            std::cerr << "Error: Failed to retrieve dynamically assigned port." << std::endl;
            close(tcp_sock);
            return -1; // Return failure if getsockname fails
        }
        tcp_port = ntohs(server_addr.sin_port); // Get the assigned port in host byte order
        std::cout << "Dynamically assigned TCP port: " << tcp_port << std::endl;
    }

    // Step 4: Start listening on the socket for incoming connections
    if (listen(tcp_sock, 10) == -1)
    { // 10 is the backlog size (number of pending connections allowed)
        std::cerr << "Error: Failed to start listening on TCP socket." << std::endl;
        close(tcp_sock);
        return -1; // Return error if listening failed
    }

    std::cout << "TCP listener initialized on " << local_ip << ":" << tcp_port << std::endl;
    return tcp_sock; // Return the TCP socket (listener socket descriptor)
}

void broadcast_presence(const std::string &local_ip, int tcp_port, std::string local_name)
{
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0); // Create UDP socket
    if (udp_sock == -1)
    {
        std::cerr << "Error: Failed to create UDP socket." << std::endl;
        return;
    }

    sockaddr_in broadcast_addr;
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_port = htons(DISCOVERY_PORT);
    broadcast_addr.sin_addr.s_addr = inet_addr("255.255.255.255"); // Broadcast to all

    int broadcast_enable = 1;
    setsockopt(udp_sock, SOL_SOCKET, SO_BROADCAST, &broadcast_enable, sizeof(broadcast_enable));

    std::string message = local_name + ":" + std::to_string(tcp_port); // Send the TCP port

    int bytes_sent = sendto(udp_sock, message.c_str(), message.size(), 0,
                            (sockaddr *)&broadcast_addr, sizeof(broadcast_addr));

    if (bytes_sent == -1)
    {
        std::cerr << "Error: Failed to broadcast presence." << std::endl;
    }
    else
    {
        std::cout << "Broadcasting presence on port " << tcp_port << "..." << std::endl;
    }

    close(udp_sock); // Close the UDP socket
}

std::tuple<std::string, std::string, int> discover_peers(const std::string &local_name, const std::string &local_ip, int tcp_port)
{
    // Create a UDP socket for listening
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock == -1)
    {
        std::cerr << "Error: Failed to create UDP socket." << std::endl;
        return {"", "", -1};
    }

    // Set up the listening address
    sockaddr_in listen_addr;
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(DISCOVERY_PORT); // Bind to the common discovery port
    listen_addr.sin_addr.s_addr = INADDR_ANY;     // Listen on all available network interfaces

    // Bind the socket to the discovery port
    if (bind(udp_sock, (sockaddr *)&listen_addr, sizeof(listen_addr)) == -1)
    {
        std::cerr << "Error: Failed to bind UDP socket to port " << DISCOVERY_PORT << "." << std::endl;
        close(udp_sock);
        return {"", "", -1};
    }

    // Set a timeout for receiving to avoid indefinite hanging
    struct timeval timeout;
    timeout.tv_sec = 5; // Timeout after 5 seconds
    timeout.tv_usec = 0;
    setsockopt(udp_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // Prepare to listen for broadcast messages
    char buffer[BUFFER_SIZE]; // Buffer for receiving messages
    sockaddr_in sender_addr;  // Address structure to store sender information
    socklen_t sender_len = sizeof(sender_addr);

    std::cout << "Listening for peer broadcasts on UDP port " << DISCOVERY_PORT << "..." << std::endl;

    // Receive broadcast messages in a loop
    while (true)
    {
        memset(buffer, 0, BUFFER_SIZE); // Clear the buffer for each new message

        // Receive a broadcast message
        int bytes_received = recvfrom(udp_sock, buffer, BUFFER_SIZE, 0, (sockaddr *)&sender_addr, &sender_len);
        if (bytes_received > 0)
        {
            std::string peer_ip = inet_ntoa(sender_addr.sin_addr); // Extract the peer's IP address
            std::string message(buffer);                           // Message contains peer_name:tcp_port

            // Parse the message to extract peer_name and tcp_port
            size_t separator_pos = message.find(":"); // if failed , returns npos
            if (separator_pos == std::string::npos)
            {
                std::cerr << "Error: Incorrect message format." << std::endl;
                continue; // Wait for a correct message
            }

            std::string peer_name = message.substr(0, separator_pos);
            int peer_tcp_port = std::stoi(message.substr(separator_pos + 1));

            // Ignore own broadcast
            if (peer_ip == local_ip && peer_tcp_port == tcp_port && peer_name == local_name)
            {
                std::cout << "Ignoring own broadcast: " << local_name << " " << local_ip << ":" << tcp_port << std::endl;
                continue;
            }

            // We discovered another peer, return their IP and port
            std::cout << "Discovered peer: " << peer_name << " at " << peer_ip << ":" << peer_tcp_port << std::endl;
            close(udp_sock);
            return {local_name, peer_ip, peer_tcp_port};
        }
        else if (bytes_received == -1 && errno == EWOULDBLOCK)
        {
            std::cout << "Timeout reached while waiting for broadcast. No peers discovered." << std::endl;
            break;
        }
    }

    close(udp_sock);     // Close the socket
    return {"", "", -1}; // Default return value in case no peers are discovered
}

bool establish_connection(int &connection_sock, int listening_sock, const std::string &peer_ip, int peer_port)
{
    bool connected = false;
    //  Attempt to connect to the discovered peer (client mode)
    if (!peer_ip.empty() && peer_port > 0)
    {
        // Create a TCP socket for the connection
        connection_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (connection_sock == -1)
        {
            std::cerr << "Failed to create socket for connecting to peer." << std::endl;
            return false; // Return false if socket creation failed
        }

        // Set up the peer address structure
        sockaddr_in peer_addr;
        peer_addr.sin_family = AF_INET;
        peer_addr.sin_port = htons(peer_port);
        inet_pton(AF_INET, peer_ip.c_str(), &peer_addr.sin_addr);

        // Try to connect to the peer
        if (connect(connection_sock, (sockaddr *)&peer_addr, sizeof(peer_addr)) == 0)
        {
            std::cout << "Successfully connected to peer at " << peer_ip << ":" << peer_port << std::endl;
            connected = true; // Connection successful
        }
        else
        {
            std::cerr << "Failed to connect to peer at " << peer_ip << ":" << peer_port << std::endl;
            close(connection_sock); // Close the socket since the connection failed
        }
    }

    //  If connection to peer failed or no peer was discovered, fall back to listening mode
    if (!connected)
    {
        std::cout << "No peers discovered or connection failed. Waiting for incoming connections..." << std::endl;

        // Accept an incoming connection (server mode)
        sockaddr_in client_addr;
        socklen_t client_size = sizeof(client_addr);
        connection_sock = accept(listening_sock, (sockaddr *)&client_addr, &client_size);

        if (connection_sock != -1)
        {
            std::cout << "Accepted incoming connection from peer!" << std::endl;
            connected = true; // Now we're connected to a peer
        }
        else
        {
            std::cerr << "Failed to accept incoming connection." << std::endl;
        }
    }

    return connected; // Return true if we are connected, false otherwise
}

void handle_chat_session(int connection_sock, const std::string &local_name)
{
    char buffer[256];
    std::string input_message;
    fd_set read_fds;
    struct timeval tv;

    // here local_name should be the name of the other peer, so not good
    std::cout << "Chat session started with peer: " << local_name << std::endl;
    while (true)
    {
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        FD_SET(connection_sock, &read_fds);

        tv.tv_sec = 0;
        tv.tv_usec = 100000; // 100ms timeout

        int max_fd = std::max(STDIN_FILENO, connection_sock) + 1;
        int activity = select(max_fd, &read_fds, NULL, NULL, &tv);

        if (activity < 0)
        {
            std::cerr << "Error in select: " << strerror(errno) << std::endl;
            break;
        }

        if (FD_ISSET(STDIN_FILENO, &read_fds))
        {
            std::cout << "You: ";
            std::getline(std::cin, input_message);
            std::cout << std::flush;
            if (send(connection_sock, input_message.c_str(), input_message.size(), 0) == -1)
            {
                std::cerr << "Error: Failed to send message." << std::endl;
                break;
            }

            if (input_message == "/exit")
            {
                std::cout << "Ending chat session." << std::endl;
                break;
            }
        }

        if (FD_ISSET(connection_sock, &read_fds))
        {
            memset(buffer, 0, sizeof(buffer));
            int bytes_received = recv(connection_sock, buffer, sizeof(buffer) - 1, 0);

            if (bytes_received > 0)
            {
                buffer[bytes_received] = '\0';
                std::cout << local_name << ": " << buffer << std::endl;
            }
            else if (bytes_received == 0)
            {
                std::cout << local_name << " has disconnected." << std::endl;
                break;
            }
            else
            {
                std::cerr << "Error on receiving data: " << strerror(errno) << std::endl;
                break;
            }
        }
    }

    close(connection_sock);
    std::cout << "Connection closed." << std::endl;
}

std::string get_local_ip()
{
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;
    std::string local_ip;

    // Get the network interfaces
    if (getifaddrs(&ifap) == -1)
    {
        std::cerr << "Error getting network interfaces." << std::endl;
        return "";
    }

    // Iterate over the interfaces
    for (ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr != nullptr && ifa->ifa_addr->sa_family == AF_INET)
        {
            sa = (struct sockaddr_in *)ifa->ifa_addr;
            char *ip = inet_ntoa(sa->sin_addr);
            // Ignore the loopback interface
            if (std::string(ifa->ifa_name) != "lo")
            {
                local_ip = ip;
                break;
            }
        }
    }

    // Free the interface list
    freeifaddrs(ifap);

    if (local_ip.empty())
    {
        std::cerr << "No non-loopback IP found." << std::endl;
    }

    return local_ip;
}

// void enable_non_blocking_io(int connection_sock)
// {
//     // Retrieve current socket flags
//     int flags = fcntl(connection_sock, F_GETFL, 0);
//     if (flags == -1)
//     {
//         std::cerr << "Error: Failed to retrieve flags for connection socket." << std::endl;
//         return;
//     }

//     // Set non-blocking flag
//     if (fcntl(connection_sock, F_SETFL, flags | O_NONBLOCK) == -1)
//     {
//         std::cerr << "Error: Failed to set non-blocking mode for connection socket." << std::endl;
//     }
//     else
//     {
//         std::cout << "Non-blocking I/O enabled on connection socket." << std::endl;
//     }
// }

// end of enable non blocking

// void OLD_handle_chat_session(int connection_sock, const std::string &peer_name)
// {
//     char buffer[256];          // Buffer for storing incoming messages
//     std::string input_message; // String to store outgoing messages

//     std::cout << "Chat session started with peer: " << peer_name << std::endl;

//     // Main chat loop
//     while (true)
//     {
//         // Step 1: Display prompt for the user to type a message
//         std::cout << "You: ";
//         std::getline(std::cin, input_message); // Get input from the user

//         // Step 2: Send the user's message to the peer (blocking send)
//         if (send(connection_sock, input_message.c_str(), input_message.size(), 0) == -1)
//         {
//             std::cerr << "Error: Failed to send message." << std::endl;
//             break; // Exit if sending fails
//         }

//         if (input_message == "/exit")
//         {
//             // User typed "/exit" to end the chat session
//             std::cout << "Ending chat session." << std::endl;
//             break;
//         }

//         // Step 3: Non-blocking receive (recv) to get the peer's response
//         memset(buffer, 0, sizeof(buffer));                                         // Clear the buffer
//         int bytes_received = recv(connection_sock, buffer, sizeof(buffer) - 1, 0); // Non-blocking recv

//         if (bytes_received > 0)
//         {
//             // Successfully received a message from the peer
//             buffer[bytes_received] = '\0';                         // Null-terminate the received message
//             std::cout << peer_name << ": " << buffer << std::endl; // Display the peer's message
//         }
//         else if (bytes_received == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
//         {
//             // No data available, non-blocking mode is working, continue
//         }
//         else if (bytes_received == 0)
//         {
//             // The peer has closed the connection
//             std::cout << peer_name << " has disconnected." << std::endl;
//             break; // Exit the chat session loop
//         }
//         else
//         {
//             // Some other error occurred
//             std::cerr << "Error on receiving data: " << strerror(errno) << std::endl;
//             break;
//         }
//     }

//     // Step 4: Close the connection socket
//     close(connection_sock);
//     std::cout << "Connection closed." << std::endl;
// }
