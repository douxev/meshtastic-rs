// Golden-vector generator for `meshtastic-crypto`.
//
// Re-derives the exact algorithms used by the Meshtastic C++ firmware's
// CryptoEngine (AES-CTR packet encryption) and Channels::generateHash
// (XOR-based 8-bit channel hash), and prints the inputs/outputs as JSON
// so the Rust port can be verified byte-for-byte.
//
// References into the oracle:
//   - src/mesh/CryptoEngine.cpp:250  CryptoEngine::encryptPacket
//   - src/mesh/CryptoEngine.cpp:269  CryptoEngine::encryptAESCtr
//   - src/mesh/CryptoEngine.cpp:290  CryptoEngine::initNonce
//   - src/mesh/Channels.cpp:27       xorHash / generateHash
//   - src/mesh/Channels.cpp:228      short-PSK expansion
//   - src/mesh/Channels.h:143        defaultpsk (AES-128)
//   - src/mesh/Channels.h:147        eventpsk   (AES-256)
//
// Build: g++ -std=c++17 -O2 -Wall -Wextra -Wpedantic gen_vectors.cpp -o gen_vectors -lcrypto
//        (or just `make` — see ./Makefile)
// Run:   ./gen_vectors > vectors.json

#include <openssl/evp.h>
#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Firmware constants (mirrored from src/mesh/Channels.h)
// ---------------------------------------------------------------------------

static const uint8_t DEFAULT_PSK[16] = {
    0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
    0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01,
};

static const uint8_t EVENT_PSK[32] = {
    0x38, 0x4b, 0xbc, 0xc0, 0x1d, 0xc0, 0x22, 0xd1, 0x81, 0xbf, 0x36, 0xb8, 0x61, 0x21, 0xe1, 0xfb,
    0x96, 0xb7, 0x2e, 0x55, 0xbf, 0x74, 0x22, 0x7e, 0x9d, 0x6a, 0xfb, 0x48, 0xd6, 0x4c, 0xb1, 0xa1,
};

// ---------------------------------------------------------------------------
// Algorithms, mirrored from the firmware
// ---------------------------------------------------------------------------

// xorHash + generateHash — src/mesh/Channels.cpp:27,39
static uint8_t channel_hash(const std::string &name, const std::vector<uint8_t> &psk) {
    uint8_t h = 0;
    for (unsigned char c : name) h ^= c;
    for (uint8_t b : psk)        h ^= b;
    return h;
}

// Short-PSK expansion — src/mesh/Channels.cpp:228
// - length == 0:                   empty (no encryption)
// - length == 1, byte == 0:        empty (no encryption)
// - length == 1, byte in [1..255]: defaultpsk with last byte += (byte - 1)
// - length  < 16:                  pad to 16 zeros (AES-128)
// - length  < 32 && != 16:         pad to 32 zeros (AES-256)
// - length == 16 or 32:            unchanged
static std::vector<uint8_t> expand_psk(const std::vector<uint8_t> &psk) {
    if (psk.empty()) return {};
    if (psk.size() == 1) {
        uint8_t idx = psk[0];
        if (idx == 0) return {};
        std::vector<uint8_t> out(DEFAULT_PSK, DEFAULT_PSK + sizeof(DEFAULT_PSK));
        out.back() = static_cast<uint8_t>(out.back() + (idx - 1));
        return out;
    }
    if (psk.size() < 16) {
        std::vector<uint8_t> out = psk;
        out.resize(16, 0);
        return out;
    }
    if (psk.size() < 32 && psk.size() != 16) {
        std::vector<uint8_t> out = psk;
        out.resize(32, 0);
        return out;
    }
    return psk;
}

// Nonce construction — src/mesh/CryptoEngine.cpp:290
// 16-byte buffer: packetId (u64 LE) || fromNode (u32 LE) || 4 zero bytes.
// (The extra_nonce branch is PKI-only; channel crypto always uses 0.)
static std::array<uint8_t, 16> init_nonce(uint32_t from_node, uint64_t packet_id) {
    std::array<uint8_t, 16> nonce{};
    for (int i = 0; i < 8; ++i) nonce[i]     = static_cast<uint8_t>((packet_id >> (8 * i)) & 0xff);
    for (int i = 0; i < 4; ++i) nonce[8 + i] = static_cast<uint8_t>((from_node >> (8 * i)) & 0xff);
    // bytes 12..15 stay zero
    return nonce;
}

// AES-CTR encrypt, matching the firmware's 4-byte counter window.
//
// OpenSSL's EVP_aes_{128,256}_ctr treats the entire 16-byte IV as a
// big-endian counter. The firmware's Arduino "Crypto" library uses
// `setCounterSize(4)`, which only increments the last 4 bytes. The
// keystreams match bit-for-bit as long as (a) the counter starts at 0
// and (b) we never roll over the 4-byte window. Our firmware nonce puts
// four zero bytes at positions 12..15, so the initial counter is zero;
// packets are bounded to MAX_BLOCKSIZE = 256 bytes (16 blocks), so the
// carry never escapes the low 4 bytes. OK.
static std::vector<uint8_t> aes_ctr_encrypt(const std::vector<uint8_t> &key,
                                            const std::array<uint8_t, 16> &iv,
                                            const std::vector<uint8_t> &plaintext) {
    const EVP_CIPHER *cipher = nullptr;
    if (key.size() == 16) cipher = EVP_aes_128_ctr();
    else if (key.size() == 32) cipher = EVP_aes_256_ctr();
    else {
        std::fprintf(stderr, "unsupported AES key size: %zu\n", key.size());
        std::exit(2);
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    assert(ctx);
    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key.data(), iv.data()) != 1) std::exit(3);

    std::vector<uint8_t> out(plaintext.size() + 16);
    int outlen1 = 0, outlen2 = 0;
    if (EVP_EncryptUpdate(ctx, out.data(), &outlen1, plaintext.data(), (int)plaintext.size()) != 1) std::exit(4);
    if (EVP_EncryptFinal_ex(ctx, out.data() + outlen1, &outlen2) != 1) std::exit(5);
    EVP_CIPHER_CTX_free(ctx);
    out.resize(static_cast<size_t>(outlen1 + outlen2));
    return out;
}

// ---------------------------------------------------------------------------
// JSON emission (tiny hand-rolled, no deps)
// ---------------------------------------------------------------------------

static std::string hex(const uint8_t *p, size_t n) {
    static const char *HEX = "0123456789abcdef";
    std::string s(n * 2, '\0');
    for (size_t i = 0; i < n; ++i) {
        s[2 * i]     = HEX[p[i] >> 4];
        s[2 * i + 1] = HEX[p[i] & 0xf];
    }
    return s;
}
static std::string hex(const std::vector<uint8_t> &v) { return hex(v.data(), v.size()); }
template <size_t N> static std::string hex(const std::array<uint8_t, N> &v) { return hex(v.data(), N); }

static std::string json_escape(const std::string &s) {
    std::string out;
    out.reserve(s.size() + 2);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

static std::vector<uint8_t> bytes_from_hex(const std::string &s) {
    assert(s.size() % 2 == 0);
    std::vector<uint8_t> out(s.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        auto hex_digit = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        out[i] = static_cast<uint8_t>((hex_digit(s[2 * i]) << 4) | hex_digit(s[2 * i + 1]));
    }
    return out;
}

// ---------------------------------------------------------------------------
// Vector tables
// ---------------------------------------------------------------------------

struct ChannelHashCase {
    const char *name;
    std::string channel_name;
    std::vector<uint8_t> expanded_psk;
};

struct PskExpandCase {
    const char *name;
    std::vector<uint8_t> input;
};

struct PacketCryptoCase {
    const char *name;
    std::vector<uint8_t> psk; // already expanded (16 or 32 bytes)
    uint32_t from_node;
    uint64_t packet_id;
    std::vector<uint8_t> plaintext;
};

int main() {
    // --- channel_hash cases ---
    std::vector<ChannelHashCase> hash_cases = {
        {"empty_name_default_psk", "", std::vector<uint8_t>(DEFAULT_PSK, DEFAULT_PSK + 16)},
        {"longfast_default_psk", "LongFast", std::vector<uint8_t>(DEFAULT_PSK, DEFAULT_PSK + 16)},
        {"custom_name_default_psk", "mychannel", std::vector<uint8_t>(DEFAULT_PSK, DEFAULT_PSK + 16)},
        {"empty_name_event_psk", "", std::vector<uint8_t>(EVENT_PSK, EVENT_PSK + 32)},
        {"longfast_all_zero_aes128", "LongFast", std::vector<uint8_t>(16, 0x00)},
        {"longfast_all_ff_aes256", "LongFast", std::vector<uint8_t>(32, 0xff)},
    };

    // --- psk_expansion cases ---
    std::vector<PskExpandCase> expand_cases = {
        {"empty", {}},
        {"short_index_0", {0x00}},
        {"short_index_1", {0x01}},  // == defaultpsk unchanged
        {"short_index_2", {0x02}},  // last byte +1
        {"short_index_10", {0x0a}}, // last byte +9
        {"short_index_255", {0xff}},// last byte + 254 (wraps mod 256)
        {"aes128_custom", {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                           0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}},
        {"aes256_custom", {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                           0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                           0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}},
        {"too_short_3", {0x01, 0x02, 0x03}},                    // pads to 16
        {"too_short_17", std::vector<uint8_t>(17, 0xaa)},       // pads to 32
    };

    // --- aes_ctr_packet cases ---
    std::vector<PacketCryptoCase> packet_cases = {
        {
            "default_psk_hello",
            std::vector<uint8_t>(DEFAULT_PSK, DEFAULT_PSK + 16),
            0x12345678u, 0x0123456789abcdefULL,
            {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'},
        },
        {
            "default_psk_empty",
            std::vector<uint8_t>(DEFAULT_PSK, DEFAULT_PSK + 16),
            0xaabbccddu, 0x0000000000000001ULL,
            {},
        },
        {
            "default_psk_one_block",
            std::vector<uint8_t>(DEFAULT_PSK, DEFAULT_PSK + 16),
            1u, 1ULL,
            std::vector<uint8_t>(16, 0x00),
        },
        {
            "default_psk_multi_block",
            std::vector<uint8_t>(DEFAULT_PSK, DEFAULT_PSK + 16),
            0xdeadbeefu, 0x00000000cafef00dULL,
            std::vector<uint8_t>(64, 0x41),  // 'A' x 64 (4 AES blocks)
        },
        {
            "default_psk_unaligned",
            std::vector<uint8_t>(DEFAULT_PSK, DEFAULT_PSK + 16),
            7u, 11ULL,
            bytes_from_hex("0a1b2c3d4e5f60718293a4b5c6d7e8f9001122334455"),
        },
        {
            "event_psk_aes256",
            std::vector<uint8_t>(EVENT_PSK, EVENT_PSK + 32),
            0x55aa55aau, 0x00000000ffffffffULL,
            bytes_from_hex("08041234567890abcdef"),
        },
        {
            "event_psk_long_payload",
            std::vector<uint8_t>(EVENT_PSK, EVENT_PSK + 32),
            0x00010203u, 0x00000001000000ffULL,
            std::vector<uint8_t>(240, 0x5a),  // near MAX_BLOCKSIZE (256)
        },
        {
            "zero_from_zero_id",
            std::vector<uint8_t>(DEFAULT_PSK, DEFAULT_PSK + 16),
            0u, 0ULL,
            {'x', 'y', 'z'},
        },
    };

    // --- emit ---
    std::printf("{\n");
    std::printf("  \"$note\": \"Auto-generated by test/rust-golden-vectors/gen_vectors.cpp. Do not edit.\",\n");
    std::printf("  \"$source\": \"src/mesh/CryptoEngine.cpp + src/mesh/Channels.cpp\",\n");

    // channel_hash
    std::printf("  \"channel_hash\": [\n");
    for (size_t i = 0; i < hash_cases.size(); ++i) {
        const auto &c = hash_cases[i];
        uint8_t h = channel_hash(c.channel_name, c.expanded_psk);
        std::printf(
            "    { \"name\": \"%s\", \"channel_name\": \"%s\", \"psk_hex\": \"%s\", \"hash\": %u }%s\n",
            c.name, json_escape(c.channel_name).c_str(), hex(c.expanded_psk).c_str(),
            static_cast<unsigned>(h), (i + 1 == hash_cases.size() ? "" : ","));
    }
    std::printf("  ],\n");

    // psk_expansion
    std::printf("  \"psk_expansion\": [\n");
    for (size_t i = 0; i < expand_cases.size(); ++i) {
        const auto &c = expand_cases[i];
        auto out = expand_psk(c.input);
        std::printf(
            "    { \"name\": \"%s\", \"input_hex\": \"%s\", \"expanded_hex\": \"%s\" }%s\n",
            c.name, hex(c.input).c_str(), hex(out).c_str(),
            (i + 1 == expand_cases.size() ? "" : ","));
    }
    std::printf("  ],\n");

    // aes_ctr_packet
    std::printf("  \"aes_ctr_packet\": [\n");
    for (size_t i = 0; i < packet_cases.size(); ++i) {
        const auto &c = packet_cases[i];
        auto nonce = init_nonce(c.from_node, c.packet_id);
        auto ct = aes_ctr_encrypt(c.psk, nonce, c.plaintext);
        std::printf(
            "    { \"name\": \"%s\", \"psk_hex\": \"%s\", \"from_node\": %u, "
            "\"packet_id\": %llu, \"nonce_hex\": \"%s\", \"plaintext_hex\": \"%s\", "
            "\"ciphertext_hex\": \"%s\" }%s\n",
            c.name, hex(c.psk).c_str(), c.from_node,
            static_cast<unsigned long long>(c.packet_id), hex(nonce).c_str(),
            hex(c.plaintext).c_str(), hex(ct).c_str(),
            (i + 1 == packet_cases.size() ? "" : ","));
    }
    std::printf("  ]\n");

    std::printf("}\n");
    return 0;
}
