#include <iostream>
#include <iomanip>
#include <unistd.h>

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
// # Implement your Attack Below
// ==========================================================================


void RunStoredCommands([[maybe_unused]] simple_networking::TCPClient* client) {
  std::cout << "Running stored commands..." << std::endl;

  // TODO: recover the cookie secret

  // TODO: print the recovered cookie secret
  std::string leaked_cookie_secret("");
  PrintLeakedCookieSecret(leaked_cookie_secret);

  // TODO: login as admin and print the recovered flag (response)
  std::string admin_login_request = "login <admin_cookie_here>";
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
