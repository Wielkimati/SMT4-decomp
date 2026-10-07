/* Instruction-derived EU asynchronous orchestration, not a worker implementation.
 * See docs/recovery/resource-request.md for the supported dependency models.
 */
#include "resource_request.h"
#include <stddef.h>
_Static_assert(UINTPTR_MAX == UINT32_MAX, "Requires original 32-bit addresses");
_Static_assert(sizeof(struct smt4_resource_request_packet) == 24, "Packet size");
_Static_assert(offsetof(struct smt4_resource_request_packet, address_out) == 20,
               "Packet output offset");

/* EU 0x00155BBC. Callback fields are installed after the constructor returns. */
uint32_t *smt4_file_create_callback(const char *path, uint32_t mode,
                                    void (*callback)(struct smt4_resource_request_packet *),
                                    struct smt4_resource_request_packet *context)
{
    uint32_t *descriptor = smt4_file_create(path, mode);
    descriptor[0x130 / 4] = (uint32_t)(uintptr_t)callback;
    descriptor[0x134 / 4] = (uint32_t)(uintptr_t)context;
    return descriptor;
}

/* EU 0x002AE72C. Output clearing precedes descriptor creation. */
void smt4_resource_request_async(uint32_t path, uint8_t *address_out,
                                 uint32_t flags, smt4_resource_completion callback,
                                 uint8_t *context, uint32_t parameter)
{
    char formatted[256];
    smt4_file_clear(formatted, 256);
    if (smt4_resource_path_mode || smt4_resource_path_has_prefix(path))
        smt4_resource_format(formatted, (const char *)(uintptr_t)path);
    else
        smt4_resource_format(formatted, smt4_resource_path_format,
                             (const char *)(uintptr_t)path);
    struct smt4_resource_request_packet *packet = smt4_file_allocate(256, 256, 0, 24, 0);
    packet->address_out = address_out;
    packet->callback = callback;
    packet->context = context;
    packet->flags = flags;
    packet->parameter = parameter;
    if (address_out)
        *(uint32_t *)address_out = 0;
    uint32_t *descriptor = smt4_file_create_callback(formatted, 0,
                                                    smt4_resource_request_complete, packet);
    packet->descriptor = descriptor;
    smt4_file_set_flags(descriptor, (flags & 1u) | ((flags & 2u) << 3));
    smt4_file_set_parameter(packet->descriptor, parameter);
}

/* EU 0x002B6820. Fifth argument forwarded; sixth argument is four. */
void smt4_resource_request(uint32_t path, uint8_t *address_out, uint32_t flags,
                           smt4_resource_completion callback, uint8_t *context)
{
    smt4_resource_request_async(path, address_out, flags, callback, context, 4);
}

/* EU 0x00155B30. Callback sees the output before ownership detachment/cleanup. */
void smt4_resource_request_complete(struct smt4_resource_request_packet *packet)
{
    uint32_t *descriptor = packet->descriptor;
    if (smt4_file_failed(descriptor)) {
        if (packet->address_out)
            *(uint32_t *)packet->address_out = 0;
        if (packet->callback)
            packet->callback(0, packet->context, 0);
    } else {
        if (packet->address_out)
            *(uint32_t *)packet->address_out = descriptor[3];
        uint32_t length = descriptor[6];
        if (packet->callback)
            packet->callback(descriptor[3], packet->context, length);
        descriptor[3] = 0;
    }
    /* The original reloads this pointer after the callback. */
    smt4_file_mark_cleanup(packet->descriptor);
    smt4_resource_release((uint32_t)(uintptr_t)packet);
}
