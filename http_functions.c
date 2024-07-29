#include "proxy.h"


// Strips all whitespace from a string in-place.
bool strip_all_whitespace(char* string) {
    if (string == NULL) {
        return false;
    }
    char* unstripped_copy = Calloc(sizeof(char), 1 + strlen(string));
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
    return true;
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
// 
// If there's an error, just return -- the caller should detect the NULLity of an important field and kill itself. 
// Returns true if everything was nominally successful and false otherwise. 
bool extract_headers(char* request_string, char*** headers_array, char** body_start, size_t* num_headers) {
    // Pre-processing checks.
    if (request_string == NULL || headers_array == NULL || body_start == NULL || num_headers == NULL) {
        printf("Extraction failed: input nullity.\n");
        return false;
    }
    // Determine the end point of the header (Required).
    char* heading_terminator = strstr(request_string, "\r\n\r\n");
    if (heading_terminator == NULL) {
        printf("Extraction failed: bad double terminator.\n");
        return false;
    }
    *body_start = (char*) ((unsigned long) heading_terminator + 4 * sizeof(char));

    // Next, get the lengths of all of the segments.
    size_t segments = 0;
    char* last_segment = request_string;
    char* terminator = strstr(request_string, "\r\n");
    if (terminator == NULL) {
        printf("Extraction failed: bad single terminator.\n");
        return false;
    }
    size_t* segment_lengths = Calloc(sizeof(size_t), 1);
    while (terminator < heading_terminator) {
        segment_lengths = realloc(segment_lengths, (segments + 1) * sizeof(size_t));
        segment_lengths[segments] = (unsigned long) terminator - (unsigned long) last_segment;
        last_segment = terminator + 2;
        terminator = strstr(last_segment, "\r\n");
        if (terminator == NULL) {
            printf("Extraction failed: #2 bad terminator.\n");
            return false;
        }
        segments++;
    }
    segment_lengths = realloc(segment_lengths, (segments + 1) * sizeof(size_t));
    segment_lengths[segments] = (unsigned long) heading_terminator - (unsigned long) last_segment;
    segments++;

    if (segments < 1) {
        printf("Extraction failed: no segments.\n");
        return false;
    }


    // Copy out the specific headers.
    char** headers = Calloc(segments, sizeof(char*));
    char* cur_start = request_string;
    for (size_t i = 0; i < segments; i++) {
        char* header = Calloc(segment_lengths[i] + 1, sizeof(char));
        strncpy(header, cur_start, segment_lengths[i]);
        headers[i] = header;
        cur_start = cur_start + segment_lengths[i] + 2;
    }
    *num_headers = segments;
    *headers_array = headers;

    // Do some cleanup.
    free(segment_lengths);
    return true;
}

// Returns true if analysis was successful and false otherwise.
bool analyze_http_protocol_data(char* data_line, char** type, char** path) {
    // Pre-checks: verify that there is information that can be extracted. 
    if (data_line == NULL || type == NULL || path == NULL) {
        return false;
    }

    // Begin the extraction process. 
    char* path_prespace = strstr(data_line, " ");
    if (path_prespace == NULL) {
        return false;
    }
    char* type_prespace = strstr((char*) ( (unsigned long) path_prespace + (unsigned long) 1), " ");
    if (type_prespace == NULL) {
        return false;
    }

    // Use pointer arithmetic to calculate what needs to be copied. 
    long type_length = ((long) path_prespace - (long) data_line) / ((long) sizeof(char));
    if (type_length <= 0) {
        return false;
    }
    char* type_copy = Calloc(sizeof(char), type_length + 1);
    strncpy(type_copy, data_line, type_length);
    *type = type_copy;
    long path_length = ((long) type_prespace - (long) path_prespace) / ((long) sizeof(char)) - 1;
    char* path_copy = Calloc(sizeof(char), path_length + 1);
    strncpy(path_copy, (char*) ((unsigned long) path_prespace + sizeof(char)), path_length);
    *path = path_copy;
    return true;
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

// For finding the last index of a char in a string.
int last_index_of(char character, char* string) {
    size_t string_length = strlen(string);
    int last_index = -1;
    for (size_t i = 0; i < string_length; i++) {
        if (string[i] == character) {
            last_index = (int) i;
        }
    }
    return last_index;
}