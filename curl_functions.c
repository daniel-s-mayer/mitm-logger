#include "proxy.h"

/**
 * TODO: Mutex on writing to and reading from the generated cert files "cache".
 */
size_t write_callback(char *data, size_t size, size_t nmemb, void* ssl_void) {
    SSL *ssl = (SSL*) ssl_void;
    size_t realsize = nmemb * size;
    SSL_write(ssl, data, realsize);
    //printf("Successful return completed (%d).\n", successful_returns);
    
    return realsize;
}

/**
 * This function actually dispatches the final request for cURL processing, which then uses a callback
 * to finally return the retrieved data back to the requestor.
 * 
 * This function should support all major HTTP protocols (GET, POST, etc.)
 * 
 * TODO: Check on memory leaks r/e parsing...
 * 
 * This should return upon error. 
 * 
 * URL is Freeable
 */
void complete_curl_request(char** test_headers_array, char* test_body_start, char* url, char* request_type, SSL* ssl, size_t num_headers) {
    // PRECONDITION CHECKS //
    if (CONTRACTS) {
        // Nullity checks.
        if (!test_headers_array || !test_body_start || !url || !request_type || !ssl) {
            printf("cURL precondition nullity failed.\n");
            exit(1);
        }
    }
    // END PRECONDITION CHECKS //
    
    // Begin the cURL process. 
    // Initialize the cURL request items.
    CURL *curl;
    CURLcode res;
    curl = curl_easy_init();
    //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15); // Limit requests to 25 seconds. 
    // Set the URL.
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);

    
    // Add the headers.
    struct curl_slist* custom_headers = NULL;
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
    // CONTRACT CHECK: Verify that custom_headers is non-NULL //
    if (CONTRACTS) {
        if (!custom_headers) {
            printf("custom_headers nullity check failed!\n");
            exit(1);
        }
    }
    // END CONTRACT CHECK 
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, custom_headers);
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYSTATUS, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);


    // Add the callback function.
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, ssl);
    curl_easy_setopt(curl, CURLOPT_HEADER, 1L);

    
    // Add the request-type-dependent elements.
    if (strcmp(request_type, "GET") == 0) {
        // Nothing to do! GETs are the default.
    } else if (strcmp(request_type, "POST") == 0) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, test_body_start);
    } // Add HEAD, PUT, DELETE, etc. 


    // Make the request!
    if (CONTRACTS) {
        if (!curl) {
            printf("cURL nullity check FAILED!\n");
            exit(1);
        }
    }
    res = curl_easy_perform(curl);
    /* Check for errors */
    if (res != CURLE_OK)
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));

    // Do some cleanup.
    curl_easy_cleanup(curl);
    curl_slist_free_all(custom_headers);
}