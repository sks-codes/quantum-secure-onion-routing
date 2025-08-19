#include "../../include/pkg/onion_client.hpp"

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
OnionClient::OnionClient(std::shared_ptr<NetworkDriver> in_network_driver,
               std::shared_ptr<NetworkDriver> out_network_driver,
               std::shared_ptr<CryptoDriver> crypto_driver) {
  // Make shared variables.
  this->cli_driver = std::make_shared<CLIDriver>();
  this->crypto_driver = crypto_driver;
  this->in_network_driver = in_network_driver;
  this->out_network_driver = out_network_driver;
}

/**
 * Generates a new DH secret and replaces the keys. This function should:
 * 1) Call `DH_generate_shared_key`
 * 2) Use the resulting key in `AES_generate_key` and `HMAC_generate_key`
 * 3) Update private key variables
 */
void OnionClient::prepare_keys() {
  uint8_t pk[pqcrystals_kyber512_PUBLICKEYBYTES];
  uint8_t sk[pqcrystals_kyber512_SECRETKEYBYTES];
  pqcrystals_kyber512_ref_keypair(pk, sk);
  current_public_value = SecByteBlock(&pk[0], pqcrystals_kyber512_PUBLICKEYBYTES);
  current_private_value = SecByteBlock(&sk[0], pqcrystals_kyber512_SECRETKEYBYTES);
}

/**
 * Encrypts the given message and returns a Message struct. This function
 * should:
 * 1) Check if the DH Ratchet keys need to change; if so, update them.
 * 2) Encrypt and tag the message.
 */
Message_Message OnionClient::send(std::string plaintext, bool out) {
  // Grab the lock to avoid race conditions between the receive and send threads
  // Lock will automatically release at the end of the function.
  std::unique_lock<std::mutex> lck(this->mtx);

  SecByteBlock AES;
  SecByteBlock HMAC;
  SecByteBlock last_other_public_value;
  bool switched;
  if (out){
    AES = out_AES_key;
    HMAC = out_HMAC_key;
    last_other_public_value = out_last_other_public_value;
    switched = out_switched;
  }
  else{
    AES = in_AES_key;
    HMAC = in_HMAC_key;
    last_other_public_value = in_last_other_public_value;
    switched = in_switched;
  }

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
    if (out){
      out_AES_key = crypto_driver->AES_generate_key(shared_secret);
      out_HMAC_key = crypto_driver->HMAC_generate_key(shared_secret);
      out_switched = false;
      AES = out_AES_key;
      HMAC = out_HMAC_key;
    }
    else{
      in_AES_key = crypto_driver->AES_generate_key(shared_secret);
      in_HMAC_key =crypto_driver->HMAC_generate_key(shared_secret);
      in_switched = false;
      AES = in_AES_key;
      HMAC = in_HMAC_key;
    }
  }
  std::pair<std::string, SecByteBlock> cipher_iv = crypto_driver->AES_encrypt(AES, plaintext);
  std::string ciphertext = cipher_iv.first;
  SecByteBlock iv = cipher_iv.second;
  std::string mac = crypto_driver->HMAC_generate(HMAC, concat_msg_fields(iv, current_public_value, ciphertext));
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
std::pair<std::string, bool> OnionClient::receive(Message_Message msg, bool out) {
  // Grab the lock to avoid race conditions between the receive and send threads
  // Lock will automatically release at the end of the function.
  std::unique_lock<std::mutex> lck(this->mtx);

  SecByteBlock AES;
  SecByteBlock HMAC;
  SecByteBlock last_other_public_value;
  bool switched;
  if (out){
    AES = out_AES_key;
    HMAC = out_HMAC_key;
    last_other_public_value = out_last_other_public_value;
    switched = out_switched;
  }
  else{
    AES = in_AES_key;
    HMAC = in_HMAC_key;
    last_other_public_value = in_last_other_public_value;
  }

  if (!switched){
    if (out){
      out_last_other_public_value = msg.public_value;
      last_other_public_value = out_last_other_public_value;
    }
    else{
      in_last_other_public_value = msg.public_value;
      last_other_public_value = in_last_other_public_value;
    }
    //reading new shared secret
    uint8_t ss[pqcrystals_kyber512_BYTES];
    pqcrystals_kyber512_ref_dec(ss, &msg.ct[0], &current_private_value[0]);
    SecByteBlock shared_secret(&ss[0], pqcrystals_kyber512_BYTES);
    if (out){
      out_AES_key = crypto_driver->AES_generate_key(shared_secret);
      out_HMAC_key = crypto_driver->HMAC_generate_key(shared_secret);
      out_switched = true;
      AES = out_AES_key;
      HMAC = out_HMAC_key;
      switched = out_switched;
    }
    else{
      in_AES_key = crypto_driver->AES_generate_key(shared_secret);
      in_HMAC_key = crypto_driver->HMAC_generate_key(shared_secret);
      in_switched = true;
      AES = in_AES_key;
      HMAC = in_HMAC_key;
      switched = in_switched;
    }
  }
  std::string plaintext = crypto_driver->AES_decrypt(AES, msg.iv, msg.ciphertext);
  bool verified = crypto_driver->HMAC_verify(HMAC, concat_msg_fields(msg.iv, last_other_public_value, msg.ciphertext), msg.mac);
  return std::make_pair(plaintext, verified);
}

/**
 * Run the client.
 */
void OnionClient::run(std::string command) {
  // Initialize cli_driver.
  this->cli_driver->init();

  // Run key exchange.
  this->HandleKeyExchange(command);

  // Start msgListener thread.
  boost::thread msgListener =
      boost::thread(boost::bind(&OnionClient::ReceiveThread, this));
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
void OnionClient::HandleKeyExchange(std::string command) {
  prepare_keys();
  cli_driver->print_success("onion " + command);
  std::vector<unsigned char> pk_vec(&current_public_value[0], &current_public_value[0] + pqcrystals_kyber512_PUBLICKEYBYTES);
  // std::string mess = "siddusiddusiddu";
  // in_network_driver->send(std::vector<unsigned char>(mess.begin(), mess.end()));
  // // out_network_driver->send(std::vector<unsigned char>(mess.begin(), mess.end()));
  in_network_driver->send(pk_vec);
  out_network_driver->send(pk_vec);
  
  std::vector<unsigned char> in_other_pk = in_network_driver->read();
  in_last_other_public_value = SecByteBlock(&in_other_pk[0], pqcrystals_kyber512_PUBLICKEYBYTES);
  std::vector<unsigned char> out_other_pk = out_network_driver->read();
  out_last_other_public_value = SecByteBlock(&out_other_pk[0], pqcrystals_kyber512_PUBLICKEYBYTES);
}

/**
 * Listen for messages and print to cli_driver.
 */
void OnionClient::ReceiveThread() {
  while (true) {
    // Try reading data from the other user.
    std::vector<unsigned char> in_data;
    try {
      in_data = this->in_network_driver->read();
    } catch (std::runtime_error &_) {
      // Exit cleanly.
      this->cli_driver->print_left("Received EOF; closing connection");
      this->in_network_driver->disconnect();
      return;
    }

    // Deserialize, decrypt, and verify message.
    Message_Message in_msg;
    in_msg.deserialize(in_data);
    auto in_decrypted_data = this->receive(in_msg, false);
    if (!in_decrypted_data.second) {
      this->cli_driver->print_left("Received invalid HMAC; the following "
                                   "message may have been tampered with.");
      throw std::runtime_error("Received invalid MAC!");
    }
    in_log = in_log + in_decrypted_data.first;

    //-----------------------------------------------

    //Same thing but for out connection
    std::vector<unsigned char> out_data;
    try {
      out_data = this->out_network_driver->read();
    } catch (std::runtime_error &_) {
      // Exit cleanly.
      this->cli_driver->print_left("Received EOF; closing connection");
      this->out_network_driver->disconnect();
      return;
    }

    // Deserialize, decrypt, and verify message.
    Message_Message out_msg;
    out_msg.deserialize(out_data);
    auto out_decrypted_data = this->receive(out_msg, true);
    if (!out_decrypted_data.second) {
      this->cli_driver->print_left("Received invalid HMAC; the following "
                                   "message may have been tampered with.");
      throw std::runtime_error("Received invalid MAC!");
    }
    out_log = out_log + out_decrypted_data.first;
  }
}

/**
 * Listen for stdin and send to other party.
 */
void OnionClient::SendThread() {
  std::string plaintext;
  while (true) {
    // Encrypt and send message.
    if (in_log != "") {
      Message_Message msg = this->send(in_log, true);
      std::vector<unsigned char> data;
      msg.serialize(data);
      this->out_network_driver->send(data);
      in_log = "";
    }
    //same for out
    if (out_log != "") {
      Message_Message msg = this->send(out_log, false);
      std::vector<unsigned char> data;
      msg.serialize(data);
      this->in_network_driver->send(data);
      out_log = "";
    }
  }
}