#include <cstdint>
#include <vector>
#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <fstream>
#include <curl/curl.h>

static const uint32_t K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

inline uint32_t rotr(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }
inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
inline uint32_t bsig0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
inline uint32_t bsig1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
inline uint32_t ssig0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
inline uint32_t ssig1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

size_t writeCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realSize = size * nmemb;
    std::string *s = reinterpret_cast<std::string*>(userp);
    s->append(reinterpret_cast<char*>(contents), realSize);
    return realSize;
}

std::string downloadBook(const std::string &url) {
    CURL *curl = curl_easy_init();
    if (!curl) throw std::runtime_error("Failed to initialize curl");

    std::string content;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &content);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        throw std::runtime_error(std::string("CURL error: ") + curl_easy_strerror(res));
    }

    curl_easy_cleanup(curl);
    return content;
}

std::vector<uint8_t> padMessage(const std::string &msg) {
    std::vector<uint8_t> data(msg.begin(), msg.end());
    uint64_t bitlen = static_cast<uint64_t>(data.size()) * 8;
    data.push_back(0x80);
    while ((data.size() * 8) % 512 != 448)
        data.push_back(0x00);
    for (int i = 7; i >= 0; --i)
        data.push_back((bitlen >> (i * 8)) & 0xFF);
    return data;
}

std::vector<uint8_t> sha256(const std::string &message) {
    uint32_t H[8] = {
        0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
        0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
    };

    auto padded = padMessage(message);

    for (size_t offset = 0; offset < padded.size(); offset += 64) {
        uint32_t w[64] = {0};
        for (int t = 0; t < 16; ++t) {
            size_t i = offset + t * 4;
            w[t] = (padded[i] << 24) | (padded[i+1] << 16) |
                   (padded[i+2] << 8) | (padded[i+3]);
        }
        for (int t = 16; t < 64; ++t)
            w[t] = ssig1(w[t-2]) + w[t-7] + ssig0(w[t-15]) + w[t-16];

        uint32_t a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
        for (int t = 0; t < 64; ++t) {
            uint32_t T1 = h + bsig1(e) + ch(e,f,g) + K[t] + w[t];
            uint32_t T2 = bsig0(a) + maj(a,b,c);
            h = g; g = f; f = e; e = d + T1;
            d = c; c = b; b = a; a = T1 + T2;
        }

        H[0] += a; H[1] += b; H[2] += c; H[3] += d;
        H[4] += e; H[5] += f; H[6] += g; H[7] += h;
    }

    std::vector<uint8_t> digest(32);
    for (int i = 0; i < 8; ++i) {
        digest[4*i+0] = (H[i] >> 24) & 0xFF;
        digest[4*i+1] = (H[i] >> 16) & 0xFF;
        digest[4*i+2] = (H[i] >> 8) & 0xFF;
        digest[4*i+3] = (H[i]) & 0xFF;
    }
    return digest;
}

std::string bytesToHex(const std::vector<uint8_t> &digest) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t b : digest)
        oss << std::setw(2) << static_cast<int>(b);
    return oss.str();
}

int main() {
    std::string url = "https://quod.lib.umich.edu/cgi/r/rsv/rsv-idx?type=DIV1&byte=4697892";
    std::cout << "Downloading Book of Mark from:\n" << url << "\n\n";

    try {
        std::string text = downloadBook(url);
        std::cout << "Download complete. Computing SHA-256 hash...\n";

        std::vector<uint8_t> hash = sha256(text);
        std::cout << "\nSHA-256 hash of the Book of Mark:\n"
                  << bytesToHex(hash) << std::endl;

    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
