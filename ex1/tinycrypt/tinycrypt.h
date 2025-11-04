#ifndef TINYCRYPT_H
#define TINYCRYPT_H

#include <vector>

namespace tinycrypt {

using ByteVector = std::vector<std::byte>;

void LogError(const std::string& msg);

ByteVector EncryptAES(const ByteVector& key,
                const ByteVector& plaintext);

ByteVector DecryptAES(const ByteVector& key,
                const ByteVector& ciphertext);

ByteVector ComputeHMAC(const ByteVector& key,
                const ByteVector& data);

} // namespace tinycrypt

#endif /* !TINYCRYPT_H */
