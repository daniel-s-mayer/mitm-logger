#include "proxy.h"
#include <sys/ioctl.h>
extern sem_t acc_sem;

/**
 * The main thread function to actually process the requests. 
 * 
 * This function will handle the CONNECT (or, potentially GET/POST/etc.) request, 
 * do handshaking, and then handle or delegate out two-way communications with the destination server. 
 *
 * The socket parameter should be the integer socket ID of the connected socket. 
 * 
 * STATUS: Seems to be memory-safe and leak-free and (should) support unlimited request length. 
 * TODO: Needs support for HTTP GET, POST, etc. requests. 
 * 
 * NULLITY CHECKS DONE
 */
void* connection_thread(void* socket) {
    // PRECONDITION CHECK //
    if (CONTRACTS) {
        if (!socket) {
            printf("Connection_thread precondition failure.\n");
            exit(1);
        }
    }
    // END PRECONDITION CHECK //

    // Make the thread independent.
    // NOTE: The callback function needs to kill it...
    pthread_detach(pthread_self());


    int newsockfd = (int) socket;
    printf("connection accepted\n");

    // Read in the preliminary connection info.
    // TODO: Verify this method further.
    size_t size_multiples = 1;
    char* buf = Calloc(300, sizeof(char));
    read(newsockfd, buf, 299);
    int bytes_unread;
    ioctl(newsockfd, FIONREAD, &bytes_unread);
    while (bytes_unread > 0) {
        size_multiples++;
        char* buf_old = buf;
        char* buf_new = Calloc(size_multiples * 300, sizeof(char));
        strcpy(buf_new, buf_old);
        buf = buf_new;
        free(buf_old);
        read(newsockfd, buf + 299 * (size_multiples - 1), 299);
        ioctl(newsockfd, FIONREAD, &bytes_unread);
    }
    // CONTRACT CHECK: buf should be non-NULL //
    if (CONTRACTS) {
        if (!buf) {
            printf("Buf non-nullity contract failed.\n");
            exit(1);
        }
    }
    // END CONTRACT CHECK //

    if (strncmp(buf, "CONNECT", 7) == 0) {
        process_connect(buf, newsockfd);
        // TODO: Add different handling for (HTTP) GET, POST, etc.
    }

    close(newsockfd);
    free(buf);
    sem_post(&acc_sem);
    //pthread_kill(pthread_self(), SIGKILL);
}


/**
 * Process an HTTP CONNECT request by parsing the CONNECT request, creating the certificate,
 * handshaking the tunnel, and delegating out further processing.  
 */
void process_connect(char* buf, int newsockfd) {
    //printf("Buffer: %s \n", buf);

    // Extract the domain name from the CONNECT request. 
    // This should be sufficiently robust for CONNECT requests. 
    //char* pre_domain_space = strstr(buf, " ");
    //char* domain_start = (char*) ((unsigned long) pre_domain_space + sizeof(char));
    //char* domain_end = strstr(buf, ":");
    //size_t domain_length = ((unsigned long) domain_end - (unsigned long) domain_start) / (sizeof(char));
    //char* domain_copy = calloc(domain_length + 1, sizeof(char));
    //strncpy(domain_copy, domain_start, domain_length);

    // UPDATED CONNECT REQUEST DOMAIN EXTRACTION //
    // Get the full hostname/port by copying between the spaces, then use a custom last_index_of() to find the colon
    // and separate the port. 
    char* pre_host_space = strstr(buf, " ");
    char* post_host_space = strstr(pre_host_space + 1, " ");
    if (pre_host_space == NULL || post_host_space == NULL) {
        printf("Bad space separation\n");
        write(newsockfd, HTTP_400_RESPONSE, strlen(HTTP_400_RESPONSE));
        return;
    }
    size_t hostname_port_length = (post_host_space) - (pre_host_space + 1);
    char* hostname_port_full_copy = Calloc(hostname_port_length + 1, sizeof(char));
    strncpy(hostname_port_full_copy, pre_host_space + 1, hostname_port_length);
    int last_colon = last_index_of(':', hostname_port_full_copy);
    if (last_colon < 0) {
        printf("Bad last colon\n");
        write(newsockfd, HTTP_400_RESPONSE, strlen(HTTP_400_RESPONSE));
        return;
    }
    char* domain_copy = Calloc(last_colon + 1, sizeof(char));
    // ASSERT: domain_copy is non-NULL.
    strncpy(domain_copy, pre_host_space + 1, last_colon);
    free(hostname_port_full_copy);

    //printf("The domain is: '%s' \n", domain_copy);

    // Make the domain specified certs.
    // TODO: Take input (somewhere) of the certificate authority filenames. 
    generate_cert("myCA.pem", "myCA.crt", domain_copy);

    char* certificate_filename = Calloc(strlen(domain_copy) + 9 + strlen(CERTS_DIRECTORY) + 1, sizeof(char)); // 9 for -crt.pem
    strcpy(certificate_filename, CERTS_DIRECTORY);
	strcat(certificate_filename, domain_copy);
    strcat(certificate_filename, "-crt.pem");
    char* key_filename = Calloc(strlen(domain_copy) + 9 + strlen(CERTS_DIRECTORY) + 1, sizeof(char)); // 9 for -key.pem
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
        perror("Unable to SSL accept. Error:\n");
        ERR_print_errors_fp(stderr);
        perror("END ERROR\n");
    } else {
        accept_SSL_connection(ssl);
    }

    // Cleanup.
    SSL_CTX_free(ssl_context);
    SSL_free(ssl);
    free(domain_copy);
    free(certificate_filename);
    free(key_filename);
}

void free_headers_array(char** headers_array, size_t num_headers) {
    if (headers_array == NULL || num_headers <= 0) {
        return;
    }
    for (size_t i = 0; i < num_headers; i++) {
        free(headers_array[i]);
    }
    free(headers_array);
}
/**
 * This function (1) processes the acceptance of the SSL connection and (2) parses
 * the headers for the final to-be-proxied request, both going ahead and forwarding that
 * request to a libcurl-enabled function. 
 * 
 * TODO: Break up further (e.g. cURLing should be a separate function...)
 * 
 */
void accept_SSL_connection(SSL* ssl) {
    //printf("Successfully accepted an SSL connection!\n");
    // Read in the preliminary buffer.
    // Unfortunately, the current OpenSSL version (at least on my system) doesn't seem to really support non-blocking 
    // sockets (maybe it works on other platforms). I will therefore used a massive 
    // fixed size (3 MB); with a future library change or additional insight, I may modify this.
    //
    // Note that this memory is quickly freed again, so the impact isn't actually that large. 
    char* ssl_buf = Calloc(1024 * 500 * 3 + 1, sizeof(char));
    SSL_read(ssl, ssl_buf, 1024 * 500 * 3);
    
    // Extract the headers. 
    char** test_headers_array = NULL;
    char* test_body_start = NULL;
    char* host = NULL;
    size_t num_headers = 0;
    if (ssl_buf == NULL) {
        return;
    }
    // ssl_buf should be string-safe, 
    bool extraction_result = extract_headers(ssl_buf, &test_headers_array, &test_body_start, &num_headers); // TODO: Make header extraction do something other than segfaulting on malformed requests. 
    if (!extraction_result) {
        printf("Bad extraction.\n");
        SSL_write(ssl, HTTP_400_RESPONSE, strlen(HTTP_400_RESPONSE));
        free(ssl_buf);
        free(host);
        return;
    }
    // Extract the hostname for the destination.
    for (size_t i = 0; i < num_headers; i++) {
        if (strncasecmp(test_headers_array[i], "Host:", strlen("Host:")) == 0) {
            char* separated_section = pointer_after_first_index(test_headers_array[i], ':');
            if (separated_section == NULL) {
                return;
            }
            char* separated_section_copy = Calloc(sizeof(char), 1 + strlen(separated_section));
            strcpy(separated_section_copy, separated_section);
            bool strip_result = strip_all_whitespace(separated_section_copy);
            if (strip_result == false) {
                printf("Bad strip.\n");
                SSL_write(ssl, HTTP_400_RESPONSE, strlen(HTTP_400_RESPONSE));
                free(ssl_buf);
                free(host);
                return;
            }
            host = separated_section_copy;
            //printf("The host is: '%s' \n", separated_section_copy);
        }            
    }

    // Extract data from the upper (protocol and path) header. 
    char* request_type = NULL;
    char* request_path = NULL;
    if (!analyze_http_protocol_data(test_headers_array[0], &request_type, &request_path)) {
        printf("Bad protocol analysis.\n");
        SSL_write(ssl, HTTP_400_RESPONSE, strlen(HTTP_400_RESPONSE));
        free(ssl_buf);
        free(host);
        free(request_path);
        free(request_type);
        free_headers_array(test_headers_array, num_headers);
        SSL_shutdown(ssl);
        return;
    }
    
    // Complete some validity checking.
    if (!host || !test_body_start || !test_headers_array || !request_type || !request_path) {
        free(ssl_buf);
        free(host);
        free(request_path);
        free_headers_array(test_headers_array, num_headers);
        SSL_shutdown(ssl);
        return; // Kill the connection now -- this isn't going to go anywhere. 
    }

    // Form the final request URL. 
    char *dest_url = Calloc(strlen(request_path) + strlen(host) + strlen("https://") + 1, sizeof(char));
    strcpy(dest_url, "https://");
    strcat(dest_url, host);
    strcat(dest_url, request_path);


    // Dispatch to the cURLing function.
    complete_curl_request(test_headers_array, test_body_start, dest_url, request_type, ssl, num_headers);

    // Shut down SSL.
    free(ssl_buf);
    free(host);
    free(request_path);
    free(request_type);
    free(dest_url);
    free_headers_array(test_headers_array, num_headers);
    
    SSL_shutdown(ssl);
}