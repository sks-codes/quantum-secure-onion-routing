#pragma once

#include <iostream>
#include <mutex>

#include <boost/chrono.hpp>
#include <boost/thread.hpp>
#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>

#include "../../include-shared/messages.hpp"
#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/network_driver.hpp"

extern "C" {
#include "../../kyber/ref/api.h"
#include "../../kyber/ref/rng.h"
}

class OnionClient {
public:
  OnionClient(std::shared_ptr<NetworkDriver> in_network_driver,
              std::shared_ptr<NetworkDriver> out_network_driver,
              std::shared_ptr<CryptoDriver> crypto_driver);
  void prepare_keys();
  Message_Message send(std::string plaintext, bool out);
  std::pair<std::string, bool> receive(Message_Message ciphertext, bool out);
  void run(std::string command);
  void HandleKeyExchange(std::string command);

private:
  void ReceiveThread();
  void SendThread();

  std::mutex mtx;

  std::shared_ptr<CLIDriver> cli_driver;
  std::shared_ptr<CryptoDriver> crypto_driver;
  std::shared_ptr<NetworkDriver> in_network_driver;
  std::shared_ptr<NetworkDriver> out_network_driver;

  SecByteBlock in_AES_key;
  SecByteBlock in_HMAC_key;
  SecByteBlock out_AES_key;
  SecByteBlock out_HMAC_key;

  // Key Exchange Ratchet Fields
  bool in_switched;
  bool out_switched;
  SecByteBlock current_private_value;
  SecByteBlock current_public_value;
  SecByteBlock in_last_other_public_value;
  SecByteBlock out_last_other_public_value;
  
  std::string in_log;
  std::string out_log;
};
