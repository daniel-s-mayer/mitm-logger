#include "proxy.h"


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
// 
// If there's an error, just return -- the caller should detect the NULLity of an important field and kill itself. 
void extract_headers(char* request_string, char*** headers_array, char** body_start, size_t* num_headers) {
    // Determine the end point of the header (Required).
    char* heading_terminator = strstr(request_string, "\r\n\r\n");
    if (heading_terminator == NULL) {
        return;
    }
    *body_start = (char*) ((unsigned long) heading_terminator + 4 * sizeof(char));

    // Next, get the lengths of all of the segments.
    size_t segments = 0;
    char* last_segment = request_string;
    char* terminator = strstr(request_string, "\r\n");
    size_t* segment_lengths = calloc(sizeof(size_t), 1);
    while (terminator < heading_terminator) {
        segment_lengths = realloc(segment_lengths, (segments + 1) * sizeof(size_t));
        segment_lengths[segments] = (unsigned long) terminator - (unsigned long) last_segment;
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

    // Do some cleanup.
    free(segment_lengths);
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