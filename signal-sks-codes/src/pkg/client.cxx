#include "../../include/pkg/client.hpp"

#include <sys/ioctl.h>

#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

#include "../../include-shared/util.hpp"
#include "colors.hpp"

/**
 * Constructor. Sets up TCP socket and starts REPL
 * @param command One of "listen" or "connect"
 * @param address Address to listen on or connect to.
 * @param port Port to listen on or connect to.
 */
Client::Client(std::shared_ptr<NetworkDriver> network_driver,
               std::shared_ptr<CryptoDriver> crypto_driver) {
  // Make shared variables.
  this->cli_driver = std::make_shared<CLIDriver>();
  this->crypto_driver = crypto_driver;
  this->network_driver = network_driver;
}

/**
 * Generates a new DH secret and replaces the keys. This function should:
 * 1) Call `DH_generate_shared_key`
 * 2) Use the resulting key in `AES_generate_key` and `HMAC_generate_key`
 * 3) Update private key variables
 */
void Client::prepare_keys() {
  uint8_t pk[pqcrystals_kyber512_PUBLICKEYBYTES];
  uint8_t sk[pqcrystals_kyber512_SECRETKEYBYTES];
  pqcrystals_kyber512_ref_keypair(pk, sk);
  current_public_value = SecByteBlock(&pk[0], pqcrystals_kyber512_PUBLICKEYBYTES);
  current_private_value = SecByteBlock(&sk[0], pqcrystals_kyber512_SECRETKEYBYTES);
  addKey(current_public_value);
}

/**
 * Encrypts the given message and returns a Message struct. This function
 * should:
 * 1) Check if the DH Ratchet keys need to change; if so, update them.
 * 2) Encrypt and tag the message.
 */
Message_Message Client::send(std::string plaintext) {
  // Grab the lock to avoid race conditions between the receive and send threads
  // Lock will automatically release at the end of the function.
  std::unique_lock<std::mutex> lck(this->mtx);
  // TODO: implement me!
  SecByteBlock ct_block(1);
  if (switched){
    //sending new public key
    prepare_keys();
    //sending new shared secret
    uint8_t ss[pqcrystals_kyber512_BYTES];
    uint8_t ct[pqcrystals_kyber512_CIPHERTEXTBYTES];
    randombytes(ss, pqcrystals_kyber512_BYTES);
    pqcrystals_kyber512_ref_enc(ct, ss, &last_other_public_value[0]);
    ct_block = SecByteBlock(&ct[0], pqcrystals_kyber512_CIPHERTEXTBYTES);
    SecByteBlock shared_secret(&ss[0], pqcrystals_kyber512_BYTES);
    AES_key = crypto_driver->AES_generate_key(shared_secret);
    HMAC_key =crypto_driver->HMAC_generate_key(shared_secret);
    switched = false;
  }
  std::pair<std::string, SecByteBlock> cipher_iv = crypto_driver->AES_encrypt(AES_key, plaintext);
  std::string ciphertext = cipher_iv.first;
  SecByteBlock iv = cipher_iv.second;
  std::string mac = crypto_driver->HMAC_generate(HMAC_key, concat_msg_fields(iv, current_public_value, ciphertext));
  Message_Message message;
  message.iv = iv;
  message.public_value = current_public_value;
  message.ciphertext = ciphertext;
  message.ct = ct_block;
  message.mac = mac;
  return message;
}

/**
 * Decrypts the given Message into a tuple containing the plaintext and
 * an indicator if the MAC was valid (true if valid; false otherwise).
 * 1) Check if the DH Ratchet keys need to change; if so, update them.
 * 2) Decrypt and verify the message.
 */
std::pair<std::string, bool> Client::receive(Message_Message msg) {
  // Grab the lock to avoid race conditions between the receive and send threads
  // Lock will automatically release at the end of the function.
  std::unique_lock<std::mutex> lck(this->mtx);
  if (!switched){
    last_other_public_value = msg.public_value;
    //reading new shared secret
    uint8_t ss[pqcrystals_kyber512_BYTES];
    pqcrystals_kyber512_ref_dec(ss, &msg.ct[0], &current_private_value[0]);
    SecByteBlock shared_secret(&ss[0], pqcrystals_kyber512_BYTES);
    AES_key = crypto_driver->AES_generate_key(shared_secret);
    HMAC_key = crypto_driver->HMAC_generate_key(shared_secret);
    switched = true;
  }
  std::string plaintext = crypto_driver->AES_decrypt(AES_key, msg.iv, msg.ciphertext);
  bool verified = crypto_driver->HMAC_verify(HMAC_key, concat_msg_fields(msg.iv, last_other_public_value, msg.ciphertext), msg.mac);
  return std::make_pair(plaintext, verified);
}

/**
 * Run the client.
 */
void Client::run(std::string command) {
  // Initialize cli_driver.
  this->cli_driver->init();
  // Run key exchange.
  this->HandleKeyExchange("norm " + command);

  // Start msgListener thread.
  boost::thread msgListener =
      boost::thread(boost::bind(&Client::ReceiveThread, this));
  msgListener.detach();

  // Start sending thread.
  this->SendThread();
}

/**
 * Run key exchange. This function:
 * 1) Listen for or generate and send DHParams_Message depending on `command`.
 * `command` can be either "listen" or "connect"; the listener should `read()`
 * for params, and the connector should generate and send params.
 * 2) Initialize DH object and keys
 * 3) Send your public value
 * 4) Listen for the other party's public value
 * 5) Generate DH, AES, and HMAC keys and set local variables
 */
void Client::HandleKeyExchange(std::string command) {
  cli_driver->print_success(command);
  prepare_keys();
  std::vector<unsigned char> pk_vec(&current_public_value[0], &current_public_value[0] + pqcrystals_kyber512_PUBLICKEYBYTES);
  network_driver->send(pk_vec);
  // std::string mess = "siddusiddusiddu"+ command;
  // network_driver->send(std::vector<unsigned char>(mess.begin(), mess.end()));
  std::vector<unsigned char> other_pk = network_driver->read();
  last_other_public_value = SecByteBlock(&other_pk[0], pqcrystals_kyber512_PUBLICKEYBYTES);
  }

/**
 * Listen for messages and print to cli_driver.
 */
void Client::ReceiveThread() {
  while (true) {
    // Try reading data from the other user.
    std::vector<unsigned char> data;
    try {
      data = this->network_driver->read();
    } catch (std::runtime_error &_) {
      // Exit cleanly.
      this->cli_driver->print_left("Received EOF; closing connection");
      this->network_driver->disconnect();
      return;
    }

    // Deserialize, decrypt, and verify message.
    Message_Message msg;
    msg.deserialize(data);
    auto decrypted_data = this->receive(msg);
    if (!decrypted_data.second) {
      this->cli_driver->print_left("Received invalid HMAC; the following "
                                   "message may have been tampered with.");
      throw std::runtime_error("Received invalid MAC!");
    }
    this->cli_driver->print_left(std::get<0>(decrypted_data));
  }
}

/**
 * Listen for stdin and send to other party.
 */
void Client::SendThread() {
  std::string plaintext;
  while (true) {
    // Read from STDIN.
    std::getline(std::cin, plaintext);
    if (std::cin.eof()) {
      this->cli_driver->print_left("Received EOF; closing connection");
      this->network_driver->disconnect();
      return;
    }

    // Encrypt and send message.
    if (plaintext != "") {
      Message_Message msg = this->send(plaintext);
      std::vector<unsigned char> data;
      msg.serialize(data);
      this->network_driver->send(data);
    }
    this->cli_driver->print_right(plaintext);
  }
}