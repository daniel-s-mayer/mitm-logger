#include "proxy.h"

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
    close(newsockfd);
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