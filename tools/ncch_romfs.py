"""Bounded, read-only NCCH v2 / IVFC RomFS path research.

New project implementation from 3dbrew's NCCH and RomFS format descriptions.
No CTRTool code/imports. See docs/recovery/ncch-romfs.md for provenance and limits.
Hash buckets, IVFC hashes, signatures and unvisited tree links are not verified.
Strict admission limits are research policy, not recovered game behavior.
"""

from dataclasses import dataclass
import struct


NONE = 0xFFFFFFFF
U64 = (1 << 64) - 1


def extent(offset, size, limit, label):
    """Check without fixed-width wrap or an allocation proportional to a bad size."""
    if min(offset, size, limit) < 0 or limit > U64 or offset > limit or size > limit - offset:
        raise ValueError(f"{label}: extent outside parent")
    return offset + size


def align(value, unit):
    extent(value, unit - 1, U64, "alignment")
    return (value + unit - 1) // unit * unit


@dataclass(frozen=True)
class Limits:
    metadata_bytes: int = 16 * 1024 * 1024
    records: int = 100_000
    name_bytes: int = 1024
    depth: int = 32
    file_bytes: int = 16 * 1024 * 1024
    read_bytes: int = 64 * 1024 * 1024

    def __post_init__(self):
        if any(not isinstance(v, int) or v <= 0 or v > U64 for v in vars(self).values()):
            raise ValueError("Limits must be positive bounded integers")


class Reader:
    def __init__(self, stream, size, limits):
        extent(0, size, U64, "input")
        stream.seek(0, 2)
        if stream.tell() != size:
            raise ValueError("Input size changed before parsing")
        self.stream, self.size, self.limits = stream, size, limits
        self.bytes_read = 0

    def read(self, offset, size):
        extent(offset, size, self.size, "read")
        extent(self.bytes_read, size, self.limits.read_bytes, "read budget")
        self.stream.seek(offset)
        result = self.stream.read(size)
        if len(result) != size:
            raise ValueError("Truncated input during read")
        self.bytes_read += size
        return result


def ncch(reader):
    h = reader.read(0, 0x200)
    if h[0x100:0x104] != b"NCCH":
        raise ValueError("NCCH magic mismatch")
    version = struct.unpack_from("<H", h, 0x112)[0]
    flags = h[0x188:0x190]
    if version != 2 or flags[6] != 0:
        raise ValueError("Unsupported NCCH version or media-unit exponent")
    if not flags[7] & 4 or flags[7] & 2:
        raise ValueError("Encrypted or unmountable RomFS unsupported")
    if flags[4] != 1 or flags[5] != 3:
        raise ValueError("Expected CTR executable/application with RomFS")
    size = struct.unpack_from("<I", h, 0x104)[0] * 512
    if size != reader.size:
        raise ValueError("NCCH declared size differs from input size")
    exheader = struct.unpack_from("<I", h, 0x180)[0]
    if exheader != 0x400:
        raise ValueError("Unsupported executable ExHeader size")
    occupied = [(0, extent(0, 0x200 + 2 * exheader, size, "NCCH headers"))]
    regions = {}
    for name, field in (("plain", 0x190), ("logo", 0x198), ("exefs", 0x1A0), ("romfs", 0x1B0)):
        off, count = struct.unpack_from("<II", h, field)
        off, count = off * 512, count * 512
        if bool(off) != bool(count) or (not count and name in ("exefs", "romfs")):
            raise ValueError(f"Invalid {name} offset/size pair")
        end = extent(off, count, size, name)
        if count:
            if any(off < b and a < end for a, b in occupied):
                raise ValueError(f"Overlapping NCCH region: {name}")
            occupied.append((off, end))
        regions[name] = {"offset": off, "size": count}
    for name, field in (("exefs", 0x1A8), ("romfs", 0x1B8)):
        hashed = struct.unpack_from("<I", h, field)[0] * 512
        if not hashed:
            raise ValueError(f"Missing {name} hash-region extent")
        extent(0, hashed, regions[name]["size"], f"{name} hash region")
        regions[name]["hash_region_size"] = hashed
    try:
        product = h[0x150:0x160].rstrip(b"\0").decode("ascii")
    except UnicodeError as error:
        raise ValueError("Malformed NCCH product code") from error
    return {"version": version, "size": size, "flags": flags.hex(),
            "program_id": f"{struct.unpack_from('<Q', h, 0x118)[0]:016x}",
            "partition_id": f"{struct.unpack_from('<Q', h, 0x108)[0]:016x}",
            "product_code": product, "exheader_size": exheader, "regions": regions}


def ivfc(reader, region):
    base, size = region["offset"], region["size"]
    extent(0, 0x60, size, "IVFC header")
    h = reader.read(base, 0x60)
    if h[:4] != b"IVFC" or struct.unpack_from("<I", h, 4)[0] != 0x10000:
        raise ValueError("Unsupported IVFC magic/version")
    if struct.unpack_from("<II", h, 0x54) != (0x5C, 0):
        raise ValueError("Unsupported IVFC header/optional-info profile")
    master = struct.unpack_from("<I", h, 8)[0]
    if not master or master % 32:
        raise ValueError("Invalid IVFC master-hash extent")
    extent(0x60, master, size, "IVFC master hashes")
    levels = []
    for off in (0xC, 0x24, 0x3C):
        logical, length, exponent, reserved = struct.unpack_from("<QQII", h, off)
        if exponent != 12 or reserved or not length:
            raise ValueError("Unsupported IVFC level profile")
        extent(logical, length, U64, "IVFC logical level")
        levels.append({"logical_offset": logical, "size": length, "block_exponent": exponent})
    # Supported on-disk order: header/master, level 3 data, level 1, level 2.
    # Logical offsets describe the separate 1,2,3 order; L3's logical offset
    # must never be used as its physical offset in the container.
    if levels[0]["logical_offset"] != 0:
        raise ValueError("Unsupported IVFC logical origin")
    for before, after in zip(levels, levels[1:]):
        if after["logical_offset"] != align(before["logical_offset"] + before["size"], 4096):
            raise ValueError("Unsupported IVFC logical layout")
    l3 = align(0x60 + master, 4096)
    end3 = extent(l3, levels[2]["size"], size, "IVFC physical level 3")
    l1 = align(end3, 4096)
    l2 = l1 + levels[1]["logical_offset"]
    for level, physical in zip(levels, (l1, l2, l3)):
        extent(physical, level["size"], size, "IVFC physical level")
        level["physical_offset"] = physical
    return {"master_hash_size": master, "levels": levels,
            "level3_ncch_offset": base + l3, "hashes_verified": False}


def component(name):
    if not name or name in (".", "..") or any(c in name for c in ("/", "\\", "\0", ":")):
        raise ValueError("Malformed path component")
    if any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in name):
        raise ValueError("Malformed path component encoding")
    return name


def records(raw, is_dir, limits):
    """Index exact record boundaries; graph edges are checked only when visited."""
    result, offset = {}, 0
    fixed = 24 if is_dir else 32
    while offset < len(raw):
        if len(result) >= limits.records:
            raise ValueError("Metadata record budget exceeded")
        extent(offset, fixed, len(raw), "metadata fixed record")
        length = struct.unpack_from("<I", raw, offset + fixed - 4)[0]
        if length % 2 or length > limits.name_bytes:
            raise ValueError("Malformed or over-budget metadata name length")
        end = extent(offset + fixed, align(length, 4), len(raw), "metadata name")
        try:
            name = raw[offset + fixed:offset + fixed + length].decode("utf-16-le", errors="strict")
        except UnicodeError as error:
            raise ValueError("Malformed UTF-16 metadata name") from error
        if not (is_dir and offset == 0 and not name):
            component(name)
        fields = struct.unpack_from("<6I" if is_dir else "<IIQQII", raw, offset)
        item = {"offset": offset, "parent": fields[0], "sibling": fields[1], "name": name}
        if is_dir:
            item.update(child=fields[2], file=fields[3], hash_link=fields[4])
        else:
            item.update(data_offset=fields[2], size=fields[3], hash_link=fields[4])
        result[offset] = item
        offset = end
    return result


class RomFS:
    def __init__(self, reader, wrapper):
        self.reader = reader
        self.base = wrapper["level3_ncch_offset"]
        self.size = wrapper["levels"][2]["size"]
        extent(0, 40, self.size, "RomFS header")
        fields = struct.unpack("<10I", reader.read(self.base, 40))
        if fields[0] != 40:
            raise ValueError("Unsupported RomFS header length")
        end, total = 40, 0
        self.tables = {}
        for name, index in (("directory_hash", 1), ("directory_metadata", 3),
                            ("file_hash", 5), ("file_metadata", 7)):
            off, size = fields[index:index + 2]
            if off % 4 or size % 4 or off < end:
                raise ValueError("Overlapping, unordered or unaligned RomFS tables")
            end = extent(off, size, self.size, name)
            total = extent(total, size, reader.limits.metadata_bytes, "metadata budget")
            self.tables[name] = {"offset": off, "size": size}
        self.data = fields[9]
        if self.data % 16 or self.data < end:
            raise ValueError("Invalid RomFS file-data alignment/overlap")
        extent(self.data, 0, self.size, "file-data origin")
        maps = []
        for name, is_dir in (("directory_metadata", True), ("file_metadata", False)):
            table = self.tables[name]
            maps.append(records(reader.read(self.base + table["offset"], table["size"]),
                                is_dir, reader.limits))
        self.dirs, self.files = maps
        if len(self.dirs) + len(self.files) > reader.limits.records:
            raise ValueError("Combined metadata record budget exceeded")
        root = self.dirs.get(0)
        if not root or root["parent"] != 0 or root["sibling"] != NONE or root["name"]:
            raise ValueError("Malformed RomFS root")
        self.visited = []

    def siblings(self, first, parent, mapping, ancestors=()):
        seen, names, items = set(), set(), []
        offset = first
        while offset != NONE:
            if offset in seen or offset in ancestors:
                raise ValueError("RomFS directory/file cycle")
            if offset not in mapping:
                raise ValueError("RomFS link is not a record boundary")
            item = mapping[offset]
            if item["parent"] != parent:
                raise ValueError("RomFS parent mismatch")
            if item["name"] in names:
                raise ValueError("Ambiguous duplicate RomFS sibling name")
            seen.add(offset)
            names.add(item["name"])
            items.append(item)
            offset = item["sibling"]
        self.visited.append({"parent": parent, "kind": "directory" if mapping is self.dirs else "file",
                             "offsets": sorted(seen)})
        return items

    def read_path(self, path):
        parts = path.split("/")
        if len(parts) > self.reader.limits.depth:
            raise ValueError("Path depth budget exceeded")
        for part in parts:
            component(part)
        parent, ancestors, selected = 0, {0}, []
        for name in parts[:-1]:
            siblings = self.siblings(self.dirs[parent]["child"], parent, self.dirs, ancestors)
            matches = [item for item in siblings if item["name"] == name]
            if not matches:
                raise ValueError("RomFS directory not found")
            item = matches[0]
            parent = item["offset"]
            ancestors.add(parent)
            selected.append(item)
        siblings = self.siblings(self.dirs[parent]["file"], parent, self.files)
        matches = [item for item in siblings if item["name"] == parts[-1]]
        if not matches:
            raise ValueError("RomFS file not found")
        item = matches[0]
        extent(item["data_offset"], item["size"], self.size - self.data, "selected file data")
        if item["size"] > self.reader.limits.file_bytes:
            raise ValueError("Selected file exceeds output budget")
        absolute = self.base + self.data + item["data_offset"]
        data = self.reader.read(absolute, item["size"])
        return data, {"path": path, "selected_directories": selected, "selected_file": item,
                      "file_ncch_offset": absolute, "file_data_level3_offset": self.data,
                      "tables": self.tables, "directory_records_indexed": len(self.dirs),
                      "file_records_indexed": len(self.files), "visited_sibling_lists": self.visited}


def read_file(stream, size, path, limits=None):
    reader = Reader(stream, size, limits or Limits())
    header = ncch(reader)
    wrapper = ivfc(reader, header["regions"]["romfs"])
    filesystem = RomFS(reader, wrapper)
    data, traversal = filesystem.read_path(path)
    return data, {"ncch": header, "ivfc": wrapper, "romfs": traversal,
                  "parser_bytes_read": reader.bytes_read, "limits": vars(reader.limits)}
