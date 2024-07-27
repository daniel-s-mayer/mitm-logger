/******
 * TODO: Add memory error checking EVERYWHERE where memory is used/copied/allocated; this will avoid
 * nonsense segfaults.
 * 
 * This include Stevens-style wrappers; in my opinion, crashing is fine. 
 * 
 * Also, think about further freeing -- current wastage is appalling.
 * 
 * Program now requires -- or look into programmatically creating -- a "certs" directory. 
 */


/**
 * 
 * NEED TO FINISH UPDATING THIS FILE TO INCLUDE THE DIRECTORY FOR CERTS!
 */


#include "proxy.h"

#define PORT 13000


/**
 * The main entry point for the proxy server.
 * 
 * The function operates a listening loop on the specified port (TODO: Make said port a cmdline arg),
 * spawning a new thread to actually process the requests. 
 */
int main() {
    // Immediately try to create the certs directory.
    // This way, we only try to do it once per execution.
    errno = 0;
    int dir_result = mkdir(CERTS_DIRECTORY, 0755);
    if (dir_result != 0 && errno != EEXIST){
        // This is a real error.
        printf("Error: Could not create a certs directory.\n");
        exit(1);   
    }


    signal(SIGPIPE, SIG_IGN);
    
    // Create the socket for the listening port. 
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("webserver (socket)");
        return 1;
    }
    struct sockaddr_in host_addr;
    int host_addrlen = sizeof(host_addr);

    host_addr.sin_family = AF_INET;
    host_addr.sin_port = htons(PORT);
    host_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    // Bind the socket to the address
    if (bind(sockfd, (struct sockaddr *)&host_addr, host_addrlen) != 0) {
        perror("webserver (bind)");
        return 1;
    }

    // Listen for incoming connections
    if (listen(sockfd, SOMAXCONN) != 0) {
        perror("webserver (listen)");
        return 1;
    }

    // Accept the connections. 
    printf("Ready for connections on port %d \n", PORT);
    while (1) {
        // Accept the connection.
        int newsockfd = accept(sockfd, (struct sockaddr *)&host_addr,
                               (socklen_t *)&host_addrlen);
                               // where socketfd is the socket you want to make non-blocking

        if (newsockfd < 0) {
            perror("webserver (accept)");
            continue;
        }
        // Start the thread.
        pthread_t thread;
        pthread_create(&thread, NULL, connection_thread, (void*) newsockfd);
    }
}
