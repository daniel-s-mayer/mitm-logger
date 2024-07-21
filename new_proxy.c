#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <curl/curl.h>
#include <ctype.h>
#include <signal.h>
#include "proxy.h"

#define PORT 13000
#define HTTP_CONNECT_RESPONSE "HTTP/1.0 200 Connection Established\r\n\r\n"
#define SIMPLE_GET_RESPONSE "HTTP/1.1 200 OK\r\nContent-Length: 12\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello World!"

size_t write_callback(char *data, size_t size, size_t nmemb, void *ssl_void)
{
    SSL *ssl = (SSL *)ssl_void;
    size_t realsize = nmemb * size;
    SSL_write(ssl, data, realsize);
    printf("Realsize %lu for data  \n", realsize);
    return realsize;
}



// Strips all whitespace from a string in-place.
char* strip_all_whitespace(char* string) {
    char* unstripped_copy = calloc(sizeof(char), 1 + strlen(string));
    strncpy(unstripped_copy, string, strlen(string));
    size_t string_length = strlen(string);
    memset(string, '\0', string_length);
    size_t current_string_copy_index = 0;
    for (size_t i = 0; i < string_length; i++) {
        if (isspace(unstripped_copy[i])) {
            continue;
        } else {
            string[current_string_copy_index] = unstripped_copy[i];
            current_string_copy_index++;
        }
    }
    free(unstripped_copy);
}

// Returns a pointer to the string after the first index of the requested character.
// Make sure not to try to free the returned pointer!
// Example: Useful for getting a pointer after the : separator in a header.
char* pointer_after_first_index(char* string, char search_char) {
    size_t string_length = strlen(string);
    for (size_t i = 0; i < string_length; i++) {
        if (string[i] == search_char) {
            return &(string[i + 1]); // Safe because there is always something -- maybe just a null terminator -- in the next position.
        }
    }
    return NULL;
}

// Extracts the raw header lines (and stores them in char*** headers_array), in addition
// to the body start (in char** body_start).
// Don't free body_start, but do free headers_array.
void extract_headers(char* request_string, char*** headers_array, char** body_start, size_t* num_headers) {
    char* heading_terminator = strstr(request_string, "\r\n\r\n");
    *body_start = (char*) ((unsigned long) heading_terminator + 4 * sizeof(char));
    // Next, get the lengths of all of the segments.
    size_t segments = 0;
    char* last_segment = request_string;
    char* terminator = strstr(request_string, "\r\n");
    size_t* segment_lengths = calloc(sizeof(size_t), 1);
    while (terminator != heading_terminator) {
        segment_lengths = realloc(segment_lengths, (segments + 1) * sizeof(size_t));
        segment_lengths[segments] = (unsigned long) terminator - (unsigned long) last_segment;
        printf("Length: %lu \n", (unsigned long) terminator - (unsigned long) last_segment);
        last_segment = terminator + 2;
        terminator = strstr(last_segment, "\r\n");
        segments++;
    }
    segment_lengths = realloc(segment_lengths, (segments + 1) * sizeof(size_t));
    segment_lengths[segments] = (unsigned long) heading_terminator - (unsigned long) last_segment;
    segments++;


    // Copy out the specific headers.
    char** headers = calloc(segments, sizeof(char*));
    char* cur_start = request_string;
    for (size_t i = 0; i < segments; i++) {
        char* header = calloc(segment_lengths[i] + 1, sizeof(char));
        strncpy(header, cur_start, segment_lengths[i]);
        headers[i] = header;
        cur_start = cur_start + segment_lengths[i] + 2;
    }
    *num_headers = segments;
    *headers_array = headers;
}
void analyze_http_protocol_data(char* data_line, char** type, char** path) {
    char* path_prespace = strstr(data_line, " ");
    char* type_prespace = strstr((char*) ( (unsigned long) path_prespace + (unsigned long) 1), " ");
    // Using pointer arithmetic.
    size_t type_length = ((unsigned long) path_prespace - (unsigned long) data_line) / (sizeof(char));
    char* type_copy = calloc(sizeof(char), type_length + 1);
    strncpy(type_copy, data_line, type_length);
    *type = type_copy;
    size_t path_length = ((unsigned long) type_prespace - (unsigned long) path_prespace) / (sizeof(char)) - 1;
    char* path_copy = calloc(sizeof(char), path_length + 1);
    strncpy(path_copy, (char*) ((unsigned long) path_prespace + sizeof(char)), path_length);
    *path = path_copy;
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


int main() {
    signal(SIGPIPE, SIG_IGN);
    // First, open the general listening (HTTP-only) port.
    // Create a socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("webserver (socket)");
        return 1;
    }
    printf("socket created successfully\n");
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
    printf("socket successfully bound to address\n");
    // Listen for incoming connections
    if (listen(sockfd, SOMAXCONN) != 0) {
        perror("webserver (listen)");
        return 1;
    }
    printf("server listening for connections\n");

    while (1) {
        // Accept incoming connections
        int newsockfd = accept(sockfd, (struct sockaddr *)&host_addr,
                               (socklen_t *)&host_addrlen);
        if (newsockfd < 0) {
            perror("webserver (accept)");
            continue;
        }
        printf("connection accepted\n");
        char buf[1001] = "";
        read(newsockfd, buf, 1000);
        printf("The request buffer was: '%s' \n", buf);
        if (strncmp(buf, "CONNECT", 7) != 0) {
            continue;
        }
        // Let's try to extract the domain name from the CONNECT request.
        // A rough way of doing it, for now...
        char* pre_domain_space = strstr(buf, " ");
        char* domain_start = (char*) ((unsigned long) pre_domain_space + sizeof(char));
        char* domain_end = strstr(buf, ":");
        size_t domain_length = ((unsigned long) domain_end - (unsigned long) domain_start) / (sizeof(char));
        char* domain_copy = calloc(domain_length + 1, sizeof(char));
        strncpy(domain_copy, domain_start, domain_length);
        printf("The domain is: %s \n", domain_copy);
        // EXPERIMENT: Generate some domain-specific certs!!
        generate_cert("myCA.pem", "myCA.crt", domain_copy);
        char* certificate_filename = calloc(domain_length + 9, sizeof(char));
        strcpy(certificate_filename, domain_copy);
        strcat(certificate_filename, "-crt.pem");
        char* key_filename = calloc(domain_length + 9, sizeof(char));
        strcpy(key_filename, domain_copy);
        strcat(key_filename, "-key.pem");
        // EXPERIMENTATION: Assume that it is a CONNECT and write the CONNECT response.
        write(newsockfd, HTTP_CONNECT_RESPONSE, strlen(HTTP_CONNECT_RESPONSE));
        // EXPERIMENTATION: Try the OpenSSL handshaking etc.
         SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
        SSL_CTX* ssl_context = create_ssl_server_context(certificate_filename, key_filename);
        if (ssl_context == NULL) {
            printf("Error (secure proxy) -- couldn't establish SSL server context. (Error: %s) \n", strerror(errno));
            return 0;
        }
        SSL* ssl = SSL_new(ssl_context);
        SSL_set_fd(ssl, newsockfd);
        if (SSL_accept(ssl) <= 0) {
            perror("Unable to SSL accept. Error:\n");
            ERR_print_errors_fp(stderr);
            perror("END ERROR\n");
        } else {
            printf("Successfully accepted an SSL connection!\n");
            char ssl_buf[1000];
            SSL_read(ssl, ssl_buf, 1000);
            printf("SSL buf: %s \n", ssl_buf);
            //SSL_write(ssl, SIMPLE_GET_RESPONSE, strlen(SIMPLE_GET_RESPONSE));
            // ** TEMPORARY HTTP ANALYSIS TESTING ** //
            char **test_headers_array = NULL;
            char *test_body_start = NULL;
            char *host = NULL;
            size_t num_headers = 0;
            extract_headers(ssl_buf, &test_headers_array, &test_body_start, &num_headers);
            printf("There are %lu headers: \n", num_headers);
            for (size_t i = 0; i < num_headers; i++)
            {
                printf("\t Header: <%s>\n", test_headers_array[i]);
                if (strncasecmp(test_headers_array[i], "Host:", strlen("Host:")) == 0)
                {
                    char *separated_section = pointer_after_first_index(test_headers_array[i], ':');
                    char *separated_section_copy = calloc(sizeof(char), 1 + strlen(separated_section));
                    strcpy(separated_section_copy, separated_section);
                    strip_all_whitespace(separated_section_copy);
                    host = separated_section_copy;
                    printf("The host is: '%s' \n", separated_section_copy);
                }
            }
            //printf("Body: %s \n", test_body_start);

            char *request_type = NULL;
            char *request_path = NULL;
            analyze_http_protocol_data(test_headers_array[0], &request_type, &request_path);
            printf("Path %s and type %s \n", request_path, request_type);
            printf("Received request buffer: %s \n", ssl_buf);

            // Experimental (GET only) cURL-ing
            // Initialize the cURL request items.
            CURL *curl;
            CURLcode res;

            curl = curl_easy_init();
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
            //  Form the request URL.
            char *dest_url = calloc(strlen(request_path) + strlen(host) + strlen("https://") + 1, sizeof(char));
            strcpy(dest_url, "https://");
            strcat(dest_url, host);
            strcat(dest_url, request_path);
            curl_easy_setopt(curl, CURLOPT_URL, dest_url);
            printf("The requested destination URL is %s \n", dest_url);
            // Add the headers.
            struct curl_slist *custom_headers = NULL;
            // Remove all of the pesky defaults.
            // custom_headers = curl_slist_append(custom_headers, "Host:"); // Blanking a header value removes it (good for defaults).
            custom_headers = curl_slist_append(custom_headers, "accept:");         // Blanking a header value removes it (good for defaults).
            custom_headers = curl_slist_append(custom_headers, "content-length:"); // Blanking a header value removes it (good for defaults).
            custom_headers = curl_slist_append(custom_headers, "content-type:");   // Blanking a header value removes it (good for defaults).
            for (size_t i = 1; i < num_headers; i++)
            {
                // Need to exclude the first path/type header line.
                custom_headers = curl_slist_append(custom_headers, test_headers_array[i]);
            }
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, custom_headers);
            //curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
            curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYSTATUS, 0L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

            // Add the callback function.
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, ssl);
            curl_easy_setopt(curl, CURLOPT_HEADER, 1L);
            // Make the request!
            res = curl_easy_perform(curl);

            /* Check for errors */
            if (res != CURLE_OK)
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            curl_easy_cleanup(curl);
        }

        // TODO: Figure out about cleaning up only after cURL has finished.
        // Probably via a struct passed into the callback.
        //SSL_shutdown(ssl);
        //SSL_CTX_free(ssl_context);
        

        //close(newsockfd);
    }


    // Have an acceptance loop.
        // Upon receipt of a CONNECT request, dump back HTTP 200
        // Quickly spin up an SSL cert for the "endpoint" (or don't for now)
        // Begin the handshake with openssl over the same file descriptor as the request was received on.
        // Read and write i.e. MITM!
        // Close SSL

}