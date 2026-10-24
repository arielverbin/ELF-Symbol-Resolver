from elfresolver.symbols import Function, String
from demo_resolver import DemoResolver

NAME = "file_inspector"


def resolve(resolver: DemoResolver) -> None:
    # Each checksum, by its constants.
    crc32 = Function().uses_const(0xEDB88320)                           # CRC-32's reversed polynomial
    adler32 = Function().uses_const(65521)                              # Adler-32's modulus: the largest prime below 2^16
    fnv1a = Function().uses_const(0x811C9DC5).uses_const(0x01000193)    # FNV-1a's offset basis, and its prime
    murmur3 = Function().uses_const(0xCC9E2D51).uses_const(0x1B873593)  # MurmurHash3's multipliers

    # What tells a file's type: the function comparing with ELF's magic number, '\x7fELF'.
    identify = Function().uses_const(0x464C457F)

    # Base64, by its alphabet.
    base64 = Function().references(String().matching("^ABCDEFGH"))

    # The report: the function calling both CRC-32 and Adler-32. Then everything it computes: every
    # function of the binary's own it calls.
    report = Function().calls(crc32).calls(adler32)
    computed = Function().called_by(report)

    resolver.resolve(crc32, "checksum::crc32")
    resolver.resolve(adler32, "checksum::adler32")
    resolver.resolve(fnv1a, "checksum::fnv1a")
    resolver.resolve(murmur3, "checksum::murmur3")
    resolver.resolve(identify, "fileinfo::identify")
    resolver.resolve(base64, "encoding::base64")
    resolver.resolve(report, "fileinfo::report")
    resolver.resolve_all(computed, [
        "checksum::crc32", "checksum::adler32", "checksum::fnv1a", "checksum::murmur3", "encoding::base64", "fileinfo::identify",
    ])

    # A constant no function uses: nothing matches.
    resolver.resolve_all(Function().uses_const(0xDEADBEEF), [])


SOURCE = r"""
// fileinfo: tells a file's type by its magic number, as `file` does, and checksums
// it every way a format or a protocol might: CRC-32 (zip, png), Adler-32 (zlib),
// FNV-1a and MurmurHash3 (hash tables), and base64 for printing. Each algorithm is
// known by its constants, which survive any compiler and any optimization.

#include <cstdint>
#include <cstdio>
#include <cstring>

// No inlining, cloning nor folding: each function stays one, as a function with many callers would.
#define KEEP __attribute__((noipa))

namespace checksum {

KEEP std::uint32_t crc32(const std::uint8_t* data, unsigned length) {
    std::uint32_t crc = 0xFFFFFFFF;
    for (unsigned i = 0; i < length; ++i) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));  // the reversed CRC-32 polynomial
    }
    return ~crc;
}

KEEP std::uint32_t adler32(const std::uint8_t* data, unsigned length) {
    constexpr std::uint32_t MODULUS = 65521;  // the largest prime below 2^16
    std::uint32_t a = 1, b = 0;
    for (unsigned i = 0; i < length; ++i) {
        a = (a + data[i]) % MODULUS;
        b = (b + a) % MODULUS;
    }
    return (b << 16) | a;
}

KEEP std::uint32_t fnv1a(const std::uint8_t* data, unsigned length) {
    std::uint32_t hash = 0x811C9DC5;  // FNV's offset basis
    for (unsigned i = 0; i < length; ++i) {
        hash ^= data[i];
        hash *= 0x01000193;           // FNV's prime
    }
    return hash;
}

KEEP std::uint32_t murmur3(const std::uint8_t* data, unsigned length, std::uint32_t seed) {
    constexpr std::uint32_t C1 = 0xCC9E2D51, C2 = 0x1B873593;
    std::uint32_t hash = seed;
    unsigned blocks = length / 4;
    for (unsigned i = 0; i < blocks; ++i) {
        std::uint32_t k;
        std::memcpy(&k, data + 4 * i, 4);
        k *= C1;
        k = (k << 15) | (k >> 17);
        k *= C2;
        hash ^= k;
        hash = (hash << 13) | (hash >> 19);
        hash = hash * 5 + 0xE6546B64;
    }
    const std::uint8_t* tail = data + 4 * blocks;
    std::uint32_t k = 0;
    switch (length & 3) {
        case 3: k ^= static_cast<std::uint32_t>(tail[2]) << 16; [[fallthrough]];
        case 2: k ^= static_cast<std::uint32_t>(tail[1]) << 8; [[fallthrough]];
        case 1:
            k ^= tail[0];
            k *= C1;
            k = (k << 15) | (k >> 17);
            k *= C2;
            hash ^= k;
    }
    hash ^= length;
    hash ^= hash >> 16;
    hash *= 0x85EBCA6B;
    hash ^= hash >> 13;
    hash *= 0xC2B2AE35;
    hash ^= hash >> 16;
    return hash;
}

}  // namespace checksum

namespace encoding {

KEEP void base64(const std::uint8_t* data, unsigned length, char* text) {
    const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned i = 0;
    for (; i + 2 < length; i += 3) {
        std::uint32_t triple = data[i] << 16 | data[i + 1] << 8 | data[i + 2];
        *text++ = alphabet[triple >> 18 & 63];
        *text++ = alphabet[triple >> 12 & 63];
        *text++ = alphabet[triple >> 6 & 63];
        *text++ = alphabet[triple & 63];
    }
    if (i < length) {
        std::uint32_t triple = data[i] << 16 | (i + 1 < length ? data[i + 1] << 8 : 0);
        *text++ = alphabet[triple >> 18 & 63];
        *text++ = alphabet[triple >> 12 & 63];
        *text++ = i + 1 < length ? alphabet[triple >> 6 & 63] : '=';
        *text++ = '=';
    }
    *text = '\0';
}

}  // namespace encoding

namespace fileinfo {

// The file's first four bytes, as a little-endian number.
KEEP const char* identify(const std::uint8_t* data, unsigned length) {
    if (length < 4)
        return "empty or tiny file";
    std::uint32_t magic;
    std::memcpy(&magic, data, 4);
    switch (magic) {
        case 0x464C457F: return "ELF executable";             // "\x7fELF"
        case 0x474E5089: return "PNG image";                  // "\x89PNG"
        case 0x04034B50: return "zip archive";                // "PK\3\4"
        case 0x46445025: return "PDF document";               // "%PDF"
        case 0xE0FFD8FF: return "JPEG image";                 // "\xff\xd8\xff\xe0"
        case 0xFEEDFACF: return "Mach-O executable (64-bit)";
    }
    if ((magic & 0xFFFF) == 0x8B1F)                          // "\x1f\x8b"
        return "gzip compressed data";
    return "data";
}

KEEP unsigned load(const char* path, std::uint8_t* buffer, unsigned capacity) {
    std::FILE* file = std::fopen(path, "rb");
    if (file == nullptr) {
        std::perror(path);
        return 0;
    }
    unsigned length = static_cast<unsigned>(std::fread(buffer, 1, capacity, file));
    std::fclose(file);
    return length;
}

KEEP void report(const char* path, const std::uint8_t* data, unsigned length) {
    char digest[64];
    std::uint32_t crc = checksum::crc32(data, length);
    encoding::base64(reinterpret_cast<const std::uint8_t*>(&crc), sizeof crc, digest);
    std::printf("%s: %s, %u bytes\n", path, identify(data, length), length);
    std::printf("  crc32    %08x (%s)\n", crc, digest);
    std::printf("  adler32  %08x\n", checksum::adler32(data, length));
    std::printf("  fnv1a    %08x\n", checksum::fnv1a(data, length));
    std::printf("  murmur3  %08x\n", checksum::murmur3(data, length, 0x9747B28C));
}

}  // namespace fileinfo

int main(int argc, char** argv) {
    static std::uint8_t buffer[1 << 20];
    for (int i = 1; i < argc; ++i) {
        unsigned length = fileinfo::load(argv[i], buffer, sizeof buffer);
        fileinfo::report(argv[i], buffer, length);
    }
    return 0;
}
"""
