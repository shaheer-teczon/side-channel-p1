#ifndef BASE64_H
#define BASE64_H

#include <string>
#include <vector>

namespace base64 {

using ByteVector = std::vector<std::byte>;

ByteVector base64_decode(std::string const& encoded_string);

std::string base64_encode(const ByteVector& bytes_to_encode);

} // namespace base64

#endif /* !BASE64_H */
