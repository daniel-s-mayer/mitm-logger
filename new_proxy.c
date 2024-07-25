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
#define HTTP_CONNECT_RESPONSE "HTTP/1.0 200 Connection Established\r\n\r\n"
#define SIMPLE_GET_RESPONSE "HTTP/1.1 200 OK\r\nContent-Length: 12\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello World!"

struct ssl_write_struct {
    void* ssl;
    int indicator;
};
typedef struct ssl_write_struct ssl_struct_t;

/**
 * TODO: Mutex on writing to and reading from the generated cert files "cache".
 */
size_t write_callback(char *data, size_t size, size_t nmemb, void* ssl_struct_void) {

    ssl_struct_t* ssl_struct = (ssl_struct_t*) ssl_struct_void;
    SSL *ssl = ssl_struct->ssl;
    size_t realsize = nmemb * size;
    SSL_write(ssl, data, realsize);
    ssl_struct->indicator = 1;
    static int successful_returns = 0;
    successful_returns++;
    //printf("Successful return completed (%d).\n", successful_returns);
    
    return realsize;
}



SSL_CTX* create_ssl_server_context(char* cert_filename, char* key_filename) {
    // Attempt to generate the SSL Server Context.
    SSL_CTX* context = SSL_CTX_new(TLS_server_method());
    if (context == NULL) {
        perror("Unable to create SSL context.\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Configure the context by adding the provided certificates.
    SSL_CTX_set_ecdh_auto(context, 1);

    if (SSL_CTX_use_certificate_file(context, cert_filename, SSL_FILETYPE_PEM) <= 0) {
        perror("Unable to read cert.pem.\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(context, key_filename, SSL_FILETYPE_PEM) <= 0) {
        perror("Unable to read key.pem.\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    return context;
}

/**
 * This function actually dispatches the final request for cURL processing, which then uses a callback
 * to finally return the retrieved data back to the requestor.
 * 
 * This function should support all major HTTP protocols (GET, POST, etc.)
 * 
 * TODO: Check on memory leaks r/e parsing...
 * 
 * URL is freeable
 */
void complete_curl_request(char** test_headers_array, char* test_body_start, char* url, char* request_type, ssl_struct_t* ssl_struct, size_t num_headers) {
    // Begin the cURL process. 
    // Initialize the cURL request items.
    CURL *curl;
    CURLcode res;
    curl = curl_easy_init();
    //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    
    // Set the URL.
    curl_easy_setopt(curl, CURLOPT_URL, url);
    printf("Requesting URL: '%s' \n", url);
    free(url);
    
    // Add the headers.
    struct curl_slist *custom_headers = NULL;
    // Remove all of the pesky defaults.
    // custom_headers = curl_slist_append(custom_headers, "Host:"); // Blanking a header value removes it (good for defaults).
    custom_headers = curl_slist_append(custom_headers, "accept:");         // Blanking a header value removes it (good for defaults).
    custom_headers = curl_slist_append(custom_headers, "content-length:"); // Blanking a header value removes it (good for defaults).
    custom_headers = curl_slist_append(custom_headers, "content-type:");   // Blanking a header value removes it (good for defaults).
    for (size_t i = 1; i < num_headers; i++) {
        // Need to exclude the first path/type header line.
        custom_headers = curl_slist_append(custom_headers, test_headers_array[i]);
    }


    // Set the various cURL control options. 
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, custom_headers);
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYSTATUS, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);


    // Add the callback function.
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, ssl_struct);
    curl_easy_setopt(curl, CURLOPT_HEADER, 1L);

    
    // Add the request-type-dependent elements.
    if (strcmp(request_type, "GET") == 0) {
        // Nothing to do! GETs are the default.
    } else if (strcmp(request_type, "POST") == 0) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, test_body_start);
    } // Add HEAD, PUT, DELETE, etc. 


    // Make the request!
    res = curl_easy_perform(curl);
    /* Check for errors */
    if (res != CURLE_OK)
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    curl_easy_cleanup(curl);
}

/**
 * This function (1) processes the acceptance of the SSL connection and (2) parses
 * the headers for the final to-be-proxied request, both going ahead and forwarding that
 * request to a libcurl-enabled function. 
 * 
 * TODO: Break up further (e.g. cURLing should be a separate function...)
 * 
 */
void accept_SSL_connection(ssl_struct_t* ssl_struct) {
    SSL* ssl = ssl_struct->ssl;
    printf("Successfully accepted an SSL connection!\n");
    // Read in the preliminary buffer.
    // Unfortunately, the current OpenSSL version (at least on my system) doesn't seem to really support non-blocking 
    // sockets (maybe it works on other platforms). I will therefore used a massive 
    // fixed size (3 MB); with a future library change or additional insight, I may modify this.
    //
    // Note that this memory is quickly freed again, so the impact isn't actually that large. 
    char* ssl_buf = calloc(1024 * 1024 * 3 + 1, sizeof(char));
    SSL_read(ssl, ssl_buf, 1024 * 1024 * 3);
    
    // Extract the headers. 
    char** test_headers_array = NULL;
    char* test_body_start = NULL;
    char* host = NULL;
    size_t num_headers = 0;
    extract_headers(ssl_buf, &test_headers_array, &test_body_start, &num_headers); // TODO: Make header extraction do something other than segfaulting on malformed requests. 
    free(ssl_buf); // The buffer is already gone!
            
    // Extract the hostname for the destination.
    for (size_t i = 0; i < num_headers; i++) {
        if (strncasecmp(test_headers_array[i], "Host:", strlen("Host:")) == 0) {
            char *separated_section = pointer_after_first_index(test_headers_array[i], ':');
            char *separated_section_copy = calloc(sizeof(char), 1 + strlen(separated_section));
            strcpy(separated_section_copy, separated_section);
            strip_all_whitespace(separated_section_copy);
            host = separated_section_copy;
            printf("The host is: '%s' \n", separated_section_copy);
        }            
    }

    // Extract data from the upper (protocol and path) header. 
    char* request_type = NULL;
    char* request_path = NULL;
    analyze_http_protocol_data(test_headers_array[0], &request_type, &request_path);
    
    // Complete some validity checking.
    if (!host || !test_body_start || !test_headers_array || !request_type || !request_path) {
        SSL_shutdown(ssl);
        return; // Kill the connection now -- this isn't going to go anywhere. 
    }

    // Form the final request URL. 
    char *dest_url = calloc(strlen(request_path) + strlen(host) + strlen("https://") + 1, sizeof(char));
    strcpy(dest_url, "https://");
    strcat(dest_url, host);
    strcat(dest_url, request_path);


    // Dispatch to the cURLing function.
    complete_curl_request(test_headers_array, test_body_start, dest_url, request_type, ssl_struct, num_headers);


    // Shut down SSL.
    SSL_shutdown(ssl);
}

/**
 * Process an HTTP CONNECT request by parsing the CONNECT request, creating the certificate,
 * handshaking the tunnel, and delegating out further processing.  
 */
void process_connect(char* buf, int newsockfd) {
    printf("Buffer: %s \n", buf);
    // Extract the domain name from the CONNECT request. 
    // This should be sufficiently robust for CONNECT requests. 
    char* pre_domain_space = strstr(buf, " ");
    char* domain_start = (char*) ((unsigned long) pre_domain_space + sizeof(char));
    char* domain_end = strstr(buf, ":");
    size_t domain_length = ((unsigned long) domain_end - (unsigned long) domain_start) / (sizeof(char));
    char* domain_copy = calloc(domain_length + 1, sizeof(char));
    strncpy(domain_copy, domain_start, domain_length);
    printf("The domain is: '%s' \n", domain_copy);

    // Make the domain specified certs.
    // TODO: Take input (somewhere) of the certificate authority filenames. 
    generate_cert("myCA.pem", "myCA.crt", domain_copy);

    char* certificate_filename = calloc(strlen(domain_copy) + 9 + strlen(CERTS_DIRECTORY) + 1, sizeof(char)); // 9 for -crt.pem
    strcpy(certificate_filename, CERTS_DIRECTORY);
	strcat(certificate_filename, domain_copy);
    strcat(certificate_filename, "-crt.pem");
    char* key_filename = calloc(strlen(domain_copy) + 9 + strlen(CERTS_DIRECTORY) + 1, sizeof(char)); // 9 for -key.pem
    strcpy(key_filename, CERTS_DIRECTORY);
	strcat(key_filename, domain_copy);
    strcat(key_filename, "-key.pem");

    // Write the CONNECT response. 
    write(newsockfd, HTTP_CONNECT_RESPONSE, strlen(HTTP_CONNECT_RESPONSE));

    // Begin the OpenSSL handshake process after the CONNECT has been handled. 
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    SSL_CTX* ssl_context = create_ssl_server_context(certificate_filename, key_filename);
    if (ssl_context == NULL) {
        printf("Error (secure proxy) -- couldn't establish SSL server context. (Error: %s) \n", strerror(errno));
        return 0;
    }
    SSL* ssl = SSL_new(ssl_context);
    
    SSL_set_fd(ssl, newsockfd);

    // Accept an SSL connection from the client. 
    if (SSL_accept(ssl) <= 0) {
        /* Set to nonblocking mode */
        if (!BIO_socket_nbio(newsockfd, 1)) {
            printf("Could not set connection socket to non-blocking ssl.\n");
            exit(1);
        }
        perror("Unable to SSL accept. Error:\n");
        ERR_print_errors_fp(stderr);
        perror("END ERROR\n");
    } else {
        ssl_struct_t* ssl_struct = calloc(1, sizeof(ssl_struct_t));
        ssl_struct->ssl = ssl;
        ssl_struct->indicator = 0;
        accept_SSL_connection(ssl_struct);
    }

    // Cleanup.
    free(domain_copy);
    free(certificate_filename);
    free(key_filename);
}

/**
 * The main thread function to actually process the requests. 
 * 
 * This function will handle the CONNECT (or, potentially GET/POST/etc.) request, 
 * do handshaking, and then handle or delegate out two-way communications with the destination server. 
 *
 * The socket parameter should be the integer socket ID of the connected socket. 
 */
void* connection_thread(void* socket) {
    // Make the thread independent.
    // NOTE: The callback function needs to kill it...
    pthread_detach(pthread_self());


    int newsockfd = (int) socket;
    printf("connection accepted\n");

    // Read in the preliminary connection info.
    // TODO: Make this support a longer request (maybe...)
    char buf[10000] = "";
    read(newsockfd, buf, 10000);
    if (strncmp(buf, "CONNECT", 7) == 0) {
        process_connect(buf, newsockfd);
        // TODO: Add different handling for GET, POST, etc.
    } else {
        return;
    }
        
    

    // NOTE: Cleanup must be done in the callback function in order to avoid trouble.
        // TODO: Figure out about cleaning up only after cURL has finished.
        // Probably via a struct passed into the callback.
        //SSL_shutdown(ssl);
        //SSL_CTX_free(ssl_context);
        

        //close(newsockfd);
    close(newsockfd);

}

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
        if (newsockfd < 0) {
            perror("webserver (accept)");
            continue;
        }
        // Start the thread.
        pthread_t thread;
        pthread_create(&thread, NULL, connection_thread, (void*) newsockfd);
    }
}