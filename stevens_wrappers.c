#include "proxy.h"
/**
 * Stevens-style wrappers for allocation functions.
 * 
 * These crash the program if memory isn't available -- this way, I can fix it!
 */

void Free(void* ptr) {
    if (!FREE_DISABLED) {
        free(ptr);
    }
}

void* Calloc(size_t nitems, size_t size) {
    void* calloc_return = calloc(nitems, size);
    if (calloc_return) {
        return calloc_return;
    } else {
        printf("Fatal error: Calloc could not allocate memory.\n");
        exit(1);
    }
}

void* Realloc(void* pointer, size_t size) {
    if (realloc(pointer, size) != pointer) {
        printf("Error! Couldn't realloc.\n");
        exit(1);
    }
    return pointer;
}
