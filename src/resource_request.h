#ifndef SMT4_RESOURCE_REQUEST_H
#define SMT4_RESOURCE_REQUEST_H
#include "resource_create.h"
#include "resource_lifecycle.h"

typedef void (*smt4_resource_completion)(uint32_t, uint8_t *, uint32_t);

/* Original 24-byte allocation; all pointers require the original 32-bit ABI. */
struct smt4_resource_request_packet {
    uint32_t *descriptor;
    smt4_resource_completion callback;
    uint8_t *context;
    uint32_t flags;
    uint32_t parameter;
    uint8_t *address_out;
};

void smt4_resource_request_async(uint32_t path, uint8_t *address_out,
                                 uint32_t flags, smt4_resource_completion callback,
                                 uint8_t *context, uint32_t parameter);
void smt4_resource_request_complete(struct smt4_resource_request_packet *packet);
uint32_t *smt4_file_create_callback(const char *path, uint32_t mode,
                                    void (*callback)(struct smt4_resource_request_packet *),
                                    struct smt4_resource_request_packet *context);
#endif
