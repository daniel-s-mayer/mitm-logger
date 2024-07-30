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
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>
#include <semaphore.h>

/******************************************************************
 * CONTRACT CHECKING: Switch to ON to test all program contracts. *
 *****************************************************************/
#define CONTRACTS 1
#define FREE_DISABLED 1 // Determines whether Free actually frees the memory. 

#define CERTS_DIRECTORY "./certs/" // WARNING: the ./ and / are necessary, with reference to the executable location, as these are used when writing the files.

#define HTTP_CONNECT_RESPONSE "HTTP/1.0 200 Connection Established\r\n\r\n"
#define SIMPLE_GET_RESPONSE "HTTP/1.1 200 OK\r\nContent-Length: 12\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello World!"
#define HTTP_400_RESPONSE "HTTP/1.1 400 Bad request\r\n\r\n"
struct ssl_write_struct {
    void* ssl;
    int indicator;
};
typedef struct ssl_write_struct ssl_struct_t;



/**
 * Connection functions (in the order they would be called in during execution).
 */
// main
void* connection_thread(void* socket);
void process_connect(char* buf, int newsockfd);
void accept_SSL_connection(SSL* ssl);

/**
 * cURL functions
 */
size_t write_callback(char *data, size_t size, size_t nmemb, void* ssl_void);
void complete_curl_request(char** test_headers_array, char* test_body_start, char* url, char* request_type, SSL* ssl, size_t num_headers);


/**
 * HTTP Processing functions
 */
bool strip_all_whitespace(char* string);
char* pointer_after_first_index(char* string, char search_char);
bool extract_headers(char* request_string, char*** headers_array, char** body_start, size_t* num_headers);
bool analyze_http_protocol_data(char* data_line, char** type, char** path);
int last_index_of(char character, char* string);


/**
 * Certificate generator functions.
 */
int generate_cert(char* ca_key_path, char* ca_crt_path, char* cert_domain);


/**
 * SSL processing functions
 */
SSL_CTX* create_ssl_server_context(char* cert_filename, char* key_filename);


/**
 * Stevens-style wrapper functions
 */
void Free(void* ptr);
void* Calloc(size_t nitems, size_t size);
void* Realloc(void* pointer, size_t size);