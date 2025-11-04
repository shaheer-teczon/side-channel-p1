#include <fstream>
#include <iostream>
#include <sstream>
#include <memory>

#include "./simple_networking.h"
#include "./tinycrypt/tinycrypt.h"

#include "base64.h"
#include "config.h"

struct handler_args {};

// TODO: read secrets from file or env variable

using ByteVector = std::vector<std::byte>;

class Server {
  // =========================================================================
  // Public Methods
  // =========================================================================
 public:
  Server() {
    server_key_ = ReadFile("./vault/private_key.secret");
    if (server_key_.size() != 16) {
      std::cerr << "[-] Invalid key size!" << std::endl;
      throw std::runtime_error("Server initialization error");
    }

    server_cookie_secret_ = ReadFile("./vault/cookie.secret");
    if (server_cookie_secret_.size() != 8) {
      std::cerr << "[-] Invalid cookie secret size!" << std::endl;
      throw std::runtime_error("Server initialization error");
    }

    flag_ = ReadFile("./vault/flag.secret");
    if (flag_.size() != 32 + std::string("SCAD{}").size()) {
      std::cerr << "[-] Invalid cookie secret size!" << std::endl;
      throw std::runtime_error("Server initialization error");
    }

    hmac_key_ = ReadFile("./vault/hmac.secret");
    if (hmac_key_.size() != 32) {
      std::cerr << "[-] Invalid HMAC secret size!" << std::endl;
      throw std::runtime_error("Server initialization error");
    }

  }
  std::string HandleClientQuery(const std::string& query) {
    if (VERBOSE_COMMANDS) {
      std::cout << "[*] Received query: " << query << std::endl;
    }
    if (StartsWith(query, "help"))       return CommandHelp(query);
    if (StartsWith(query, "get-cookie")) return CommandGetCookie(query);
    if (StartsWith(query, "login"))      return CommandLogin(query);
    if (StartsWith(query, "echo"))       return CommandEcho(query);
    if (StartsWith(query, "encrypt"))    return CommandEncrypt(query);
    return std::string("[!] Unknown command");
  }

  // =========================================================================
  // Private Methods
  // =========================================================================
 private:
  std::string ReadFile(const std::string& filename) {
    std::ifstream fstr(filename);
    if (!fstr) {
      std::cerr << "[-] Could not open file: " << filename << std::endl;
      return "";
    }
    std::stringstream buffer;
    buffer << fstr.rdbuf();
    fstr.close();
    return buffer.str();
  }

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

  bool StartsWith(const std::string& bytes, const std::string& prefix) {
    return bytes.rfind(prefix, 0) == 0;
  }
  
  std::string RemovePrefix(const std::string& bytes, const std::string& prefix) {
    if (!StartsWith(bytes, prefix)) return bytes;
    return bytes.substr(prefix.size());
  }

  // returns empty string on error
  std::string EncryptAndEncode(const std::string& plaintext) {
    // encrypt the message with AES
    ByteVector ciphertext = tinycrypt::EncryptAES(
        ByteVectorFromStr(server_key_),
        ByteVectorFromStr(plaintext));
    if (ciphertext.empty()) {
      return "";
    }

    // compute HMAC over plaintext
    ByteVector hmac_tag = tinycrypt::ComputeHMAC(
        ByteVectorFromStr(hmac_key_),
        ByteVectorFromStr(plaintext));
    
    // base64 encode message parts
    std::string ciphertext_b64 = base64::base64_encode(ciphertext);
    std::string hmac_b64 = base64::base64_encode(hmac_tag);
    if (ciphertext_b64.empty() || hmac_b64.empty()) {
      return "";
    }

    // format "<ciphertext_b64>.<hmac_b64>"
    return ciphertext_b64 + "." + hmac_b64;
  }

  std::string DecodeAndDecrypt(const std::string& encoded_payload) {
    // split at '.'
    size_t dot_pos = encoded_payload.find('.');
    if (dot_pos == std::string::npos) {
      std::cout << "[-] No dot in payload!" << std::endl;
      return "";
    }
    std::string ciphertext_b64 = encoded_payload.substr(0, dot_pos);
    std::string hmac_b64 = encoded_payload.substr(dot_pos + 1);
    if (ciphertext_b64.empty() || hmac_b64.empty()) {
      std::cout << "[-] empty error" << std::endl;
      return "";
    }

    ByteVector ciphertext = base64::base64_decode(ciphertext_b64);
    ByteVector hmac_tag = base64::base64_decode(hmac_b64);
    if (ciphertext.empty() || hmac_tag.empty()) {
      std::cout << "[-] Decoding error" << std::endl;
      return "";
    }

    // decrypt payload
    ByteVector plaintext = tinycrypt::DecryptAES(
        ByteVectorFromStr(server_key_),
        ciphertext);

    // verify HMAC
    ByteVector expected_hmac = tinycrypt::ComputeHMAC(
        ByteVectorFromStr(hmac_key_),
        plaintext
    );
    if (expected_hmac != hmac_tag) {
      return "";
    }

    return StrFromByteVector(plaintext);
  }
  
  std::string CommandHelp([[maybe_unused]] const std::string& query) {
    return std::string("Available commands:\n"
                       "get-cookie - returns cookie for invalid user 'nobody'\n"
                       "login <cookie> - login with the provided cookie\n"
                       "echo <message> - echoes back the provided message\n"
                       "encrypt <message> - encrypt the provided message\n"
                       "help - shows this help\n");
  }

  std::string CommandGetCookie([[maybe_unused]] const std::string& query) {
    // return cookie for user "nobody"
    std::string cookie_plain = std::string("nobody-") + server_cookie_secret_;
    return EncryptAndEncode(cookie_plain);
  }
  
  std::string PrintFlag() {
    std::stringstream ss;
    ss << "[+] Login successful: Welcome Admin!" << std::endl;
    ss << "[+] Here is your flag: " << flag_ << std::endl;
    return ss.str();
  }

  std::string CommandLogin([[maybe_unused]] const std::string& query) {
    std::string cookie = RemovePrefix(query, "login ");

    std::string cookie_plain = DecodeAndDecrypt(cookie);
      
    if (cookie_plain.size() == 0) {
      // make sure to respond with the same error as below
      // to prevent leaking information about decryption errors
      return std::string("[-] Login failed: invalid cookie");
    }
    // check if decrypted cookie matches "admin-<COOKIESECRET>"
    std::string expected_cookie = std::string("admin-") + server_cookie_secret_;
    if (cookie_plain == expected_cookie) {
      return PrintFlag();
    }
    return std::string("[-] Login failed: invalid cookie");
  }
  
  std::string CommandEcho(const std::string& query) {
    return RemovePrefix(query, "echo ");
  }

  
  std::string CommandEncrypt([[maybe_unused]] const std::string& query) {
    ByteVector msg_plain = base64::base64_decode(
        RemovePrefix(query, "encrypt "));
    return EncryptAndEncode(StrFromByteVector(msg_plain));
  }

  // =========================================================================
  // Member variables
  // =========================================================================
  
  // used for AES encryption/decryption
  std::string server_key_ = "";
  std::string flag_ = "";

  std::string hmac_key_ = "";

  // used to sign cookies
  std::string server_cookie_secret_ = "";
};

void ClientHandler(std::shared_ptr<Server> server, 
    int client_socket,
    simple_networking::ByteArray message) {
  (void) client_socket;

  // let server handle the query and send back the response
  std::string response = server->HandleClientQuery(message.ToString());
  simple_networking::SendNetworkMessage(client_socket, response);
}


void* target_ptr = (char*)tinycrypt::LogError + 10;
int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[]) {

  simple_networking::TCPServer tcp_server(VERBOSE_NETWORK);
  tcp_server.Bind("0.0.0.0", SERVER_PORT);
  auto server = std::make_shared<Server>();
  tcp_server.Listen<std::shared_ptr<Server>>(&ClientHandler, server, false);

  std::cout << "[+] Enter 'q' to stop server" << std::endl;
  bool stop = false;
  while (!stop) {
    int c = getchar();
    if (c == 'q' || c == 'Q') stop = true;
  }
  std::cout << "[+] Stopping server" << std::endl;
  tcp_server.StopListening();
  return 0;
}
