#include <chrono>
#include <cstddef>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <random>
#include <vector>

#include <cpuid.h>

#include "./tiny-AES-c/aes.hpp"
#include "./hmac_sha256/hmac_sha256.h"

#include "./tinycrypt.h"

namespace tinycrypt {

#define SHA256_HASH_SIZE 32

static unsigned int GetCurrentCoreId(void) {
  unsigned int eax, ebx, ecx, edx;
  // CPUID leaf 1 returns "APIC ID" in bits 24-31 of EBX
  __cpuid(0x1, eax, ebx, ecx, edx);
  unsigned int core_id = (ebx >> 24) & 0xFF;
  core_id >>= 1;  // ignore the lowest bit (encoded HT id)
  return core_id;
}

__attribute__((aligned(4096)))
void LogError(const std::string& msg) {
  int current_cpu_core = GetCurrentCoreId();
  std::stringstream ss;
  ss << "[!] CPU Core ";
  ss << std::dec << current_cpu_core;
  ss << ": ";
  ss << "Tinycrypt error: " << msg;
  std::string msg_full = ss.str();
  std::cerr << msg_full << std::endl;
}

ByteVector AppendPadding(const ByteVector& data) {
  ByteVector res = data;
  size_t pad_len = 16 - (data.size() % 16);
  if (pad_len == 0) pad_len = 16;
  for (size_t i = 0; i < pad_len; i++) {
    res.push_back(std::byte{static_cast<unsigned char>(pad_len)});
  }
  return res;
}

ByteVector RemovePadding(const ByteVector& data) {
  if (data.empty()) {
    LogError("Cannot remove padding from empty data");
    return {};
  }
  ssize_t pad_len = std::to_integer<ssize_t>(data.back());
  if (pad_len <= 0 || pad_len > 16) {
    LogError("Invalid padding detected");
    return {};
  }

  // check that padding is valid and not corrupted
  for (ssize_t i = 0; i < pad_len; i++) {
    uint8_t val = std::to_integer<size_t>(data[data.size() - 1 - i]);
    if (val != pad_len) {
      LogError("Invalid padding detected");
      return {};
    }
  }
  ByteVector res = ByteVector(
      data.begin(), 
      data.end() - pad_len);
  return res;
}

void RandomizeBytes(uint8_t* data, size_t data_length) {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dis(0, 255);
  for (size_t i = 0; i < data_length; i++) {
    data[i] = dis(gen);
  }
}

ByteVector EncryptAES(const ByteVector& key,
                const ByteVector& plaintext) {
  if (key.size() != 16) {
    LogError("Key size not 16 bytes");
    return {};
  }

  ByteVector plaintext_padded = AppendPadding(plaintext);
  
  struct AES_ctx ctx{};
  uint8_t iv[AES_BLOCKLEN] = {0};
  ByteVector result;
  RandomizeBytes(iv, AES_BLOCKLEN);
  for (size_t i = 0; i < AES_BLOCKLEN; i++) {
    // prefix the result with the IV
    result.push_back(std::byte{iv[i]});
  }
  AES_init_ctx_iv(
      &ctx, 
      reinterpret_cast<const uint8_t*>(key.data()), 
      iv);

  ByteVector ciphertext = ByteVector(plaintext_padded);
  AES_CBC_encrypt_buffer(
      &ctx, 
      reinterpret_cast<uint8_t*>(ciphertext.data()), 
      ciphertext.size());

  // prepend the ciphertext
  result.insert(result.end(), ciphertext.begin(), ciphertext.end());
  // IV + ciphertext
  return result;
}

ByteVector DecryptAES(const ByteVector& key,
                const ByteVector& iv_ciphertext) {
  if (key.size() != 16) {
    LogError("Key size not 16 bytes");
    return {};
  }
  if (iv_ciphertext.size() % 16 != 0 || iv_ciphertext.size() < AES_BLOCKLEN) {
    LogError("Ciphertext size invalid");
    return {};
  }

  struct AES_ctx ctx{};

  // 'ciphertext' includes the IV as prefix
  uint8_t iv[AES_BLOCKLEN] = {0};
  for (size_t i = 0; i < AES_BLOCKLEN; i++) {
    iv[i] = static_cast<uint8_t>(std::to_integer<int>(iv_ciphertext[i]));
  }
  ByteVector ciphertext = ByteVector(
      iv_ciphertext.begin() + AES_BLOCKLEN, 
      iv_ciphertext.end());

  AES_init_ctx_iv(
      &ctx, 
      reinterpret_cast<const uint8_t*>(key.data()), 
      iv);

  ByteVector plaintext_padded = ciphertext;
  AES_CBC_decrypt_buffer(
      &ctx, 
      reinterpret_cast<uint8_t*>(plaintext_padded.data()), 
      plaintext_padded.size());

  ByteVector plaintext = RemovePadding(plaintext_padded);
  return plaintext;
}

ByteVector ComputeHMAC(const ByteVector& key,
                const ByteVector& data) {
  if (key.empty()) {
    LogError("HMAC key size is zero");
    return {};
  }
  std::vector<uint8_t> out_raw(SHA256_HASH_SIZE);

  hmac_sha256(
      reinterpret_cast<const uint8_t*>(key.data()), 
      key.size(),
      reinterpret_cast<const uint8_t*>(data.data()), 
      data.size(),
      out_raw.data(), 
      out_raw.size());

  ByteVector out;
  for (size_t i = 0; i < SHA256_HASH_SIZE; i++) {
    out.push_back(std::byte{out_raw[i]});
  }
  return out;
}

} // namespace tinycrypt
