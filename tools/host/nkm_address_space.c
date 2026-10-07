/* Host-only adaptation of the six table/consumer contracts. Original source
 * remains in src/. See docs/recovery/nkm-host-boundary.md for the deviations.
 */
#include "nkm_address_space.h"
#include "unsigned_quotient.h"

typedef struct {
    const smt4_host_space *space;
    int status;
    uint32_t reads;
} execution;

static int valid_map(const smt4_host_space *s)
{
    size_t i, j;
    if (!s || s->region_count > 64 || (s->region_count && !s->regions))
        return 0;
    for (i = 0; i < s->region_count; ++i) {
        const smt4_host_region *r = &s->regions[i];
        uint64_t end = (uint64_t)r->address + r->size;
        if (!r->bytes || !r->size || end > UINT64_C(0x100000000))
            return 0;
        for (j = 0; j < i; ++j) {
            const smt4_host_region *other = &s->regions[j];
            if ((uint64_t)r->address < (uint64_t)other->address + other->size &&
                (uint64_t)other->address < end)
                return 0;
        }
    }
    return 1;
}

static const smt4_host_region *region_at(execution *e, uint32_t address)
{
    size_t i;
    for (i = 0; i < e->space->region_count; ++i) {
        const smt4_host_region *r = &e->space->regions[i];
        if (address >= r->address && (uint64_t)address < (uint64_t)r->address + r->size)
            return r;
    }
    return NULL;
}

static uint32_t read_le(execution *e, uint64_t address, uint32_t width)
{
    const smt4_host_region *r;
    uint32_t value = 0, i;
    if (e->status) return 0;
    if (address + width > UINT64_C(0x100000000)) {
        e->status = SMT4_HOST_ADDRESS_WRAP;
        return 0;
    }
    if (address % width) {
        e->status = SMT4_HOST_ALIGNMENT;
        return 0;
    }
    r = region_at(e, (uint32_t)address);
    if (!r || address + width > (uint64_t)r->address + r->size) {
        e->status = SMT4_HOST_UNMAPPED;
        return 0;
    }
    if (e->reads == e->space->read_budget) {
        e->status = SMT4_HOST_BUDGET;
        return 0;
    }
    ++e->reads;
    for (i = 0; i < width; ++i)
        value |= (uint32_t)r->bytes[(size_t)(address - r->address) + i] << (i * 8);
    return value;
}

static uint32_t select_section(execution *e, uint32_t base, uint32_t index)
{
    uint32_t slot, header, offset, section;
    if (!base || read_le(e, base, 4) != UINT32_C(0x52434254)) return 0;
    if (index >= read_le(e, (uint64_t)base + 8, 4) || e->status) return 0;
    slot = base + UINT32_C(12) + index * UINT32_C(4);
    header = read_le(e, (uint64_t)base + 4, 4);
    offset = read_le(e, slot, 4);
    section = base + header + offset;
    if (!section || read_le(e, section, 4) != UINT32_C(0x314C4254)) return 0;
    return section;
}

static uint32_t payload(execution *e, uint32_t section)
{
    if (!section || read_le(e, section, 4) != UINT32_C(0x314C4254)) return 0;
    return section + UINT32_C(16);
}

static uint32_t count(execution *e, uint32_t section)
{
    uint32_t stride, size;
    if (!section || read_le(e, section, 4) != UINT32_C(0x314C4254)) return 0;
    stride = read_le(e, (uint64_t)section + 8, 4);
    if (!stride || e->status) return 0;
    size = read_le(e, (uint64_t)section + 4, 4);
    if (e->status) return 0;
    return smt4_unsigned_quotient(size, stride);
}

static uint32_t resource(execution *e, uint32_t id, uint32_t index)
{
    uint32_t base = 0;
    if (id < 67)
        base = read_le(e, (uint64_t)e->space->registry_address + id * 16 + 4, 4);
    return select_section(e, base, index);
}

static uint32_t halfword(execution *e, uint32_t data, uint64_t offset)
{
    const smt4_host_region *r;
    if (e->status) return 0;
    if ((uint64_t)data + offset + 2 > UINT64_C(0x100000000)) {
        e->status = SMT4_HOST_ADDRESS_WRAP;
        return 0;
    }
    r = data ? region_at(e, data) : NULL;
    if (!r || (uint64_t)data + offset + 2 > (uint64_t)r->address + r->size) {
        e->status = SMT4_HOST_UNMAPPED;
        return 0;
    }
    return read_le(e, (uint64_t)data + offset, 2);
}

static uint32_t lookup(execution *e, uint32_t index)
{
    uint32_t section = resource(e, 1, 2);
    uint32_t data = payload(e, section);
    uint32_t entries = count(e, section);
    return halfword(e, data, index < entries ? (uint64_t)index * 4 : 0);
}

static uint32_t pairs(execution *e, uint32_t key)
{
    uint32_t section = resource(e, 1, 3);
    uint32_t data = payload(e, section);
    uint32_t index;
    for (index = 0; !e->status && index < count(e, section); ++index) {
        uint32_t candidate = halfword(e, data, (uint64_t)index * 4);
        if (e->status) break;
        if (candidate == key) {
            uint32_t value = halfword(e, data, (uint64_t)index * 4 + 2);
            return value ? value : UINT32_C(50);
        }
    }
    return UINT32_C(50);
}

int smt4_host_eval(const smt4_host_space *space, uint32_t operation,
    uint32_t arg0, uint32_t arg1, uint32_t *value, uint32_t *reads)
{
    execution e;
    uint32_t result = 0;
    if (reads) *reads = 0;
    if (!value || !valid_map(space)) return SMT4_HOST_BAD_MAP;
    e.space = space;
    e.status = SMT4_HOST_OK;
    e.reads = 0;
    switch (operation) {
    case SMT4_HOST_SELECT: result = select_section(&e, arg0, arg1); break;
    case SMT4_HOST_PAYLOAD: result = payload(&e, arg0); break;
    case SMT4_HOST_COUNT: result = count(&e, arg0); break;
    case SMT4_HOST_RESOURCE: result = resource(&e, arg0, arg1); break;
    case SMT4_HOST_LOOKUP: result = lookup(&e, arg0); break;
    case SMT4_HOST_PAIRS: result = pairs(&e, arg0); break;
    default: e.status = SMT4_HOST_BAD_OPERATION; break;
    }
    if (reads) *reads = e.reads;
    if (!e.status) *value = result;
    return e.status;
}
