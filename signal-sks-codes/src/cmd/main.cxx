#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>

#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/network_driver.hpp"
#include "../../include/pkg/client.hpp"
#include "../../include/pkg/onion_client.hpp"

/*
 * Usage: ./signal <accept|connect> [address] [port]
 * Ex: ./signal accept localhost 3000
 *     ./signal connect localhost 3000
 */
int main(int argc, char *argv[]) {
  // Input checking.
  if (argc != 4 && argc != 7 && argc != 5) {
    std::cout << "Usage: " << argv[0] << " <listen|connect> [address] [port] (onion)"
              << std::endl;
    return 1;
  }
  std::string command = argv[1];
  std::string address = argv[2];
  std::string address_onion;
  int port = atoi(argv[3]);
  int port_onion;
  bool onion_mode = false;
  if (argc == 7 || argc == 5){
    onion_mode = true;//(argv[5] == "onion")|| (argv[7] == "onion");
    if (onion_mode && argc == 7){
      address_onion = argv[4];
      port_onion = atoi(argv[5]);
    }
  }
  if (command != "listen" && command != "connect") {
    std::cout << "Usage: " << argv[0] << " <listen|connect> [address] [port] (onion)"
              << std::endl;
    return 1;
  }


  //making crypto driver
  std::shared_ptr<CryptoDriver> crypto_driver =
    std::make_shared<CryptoDriver>();

  if (onion_mode && argc == 7){
    std::shared_ptr<NetworkDriver> in_network_driver =
      std::make_shared<NetworkDriverImpl>();
    std::shared_ptr<NetworkDriver> out_network_driver =
      std::make_shared<NetworkDriverImpl>();
    in_network_driver->connect(address, port);
    out_network_driver->listen(port_onion);
    OnionClient onion_client = OnionClient(in_network_driver, out_network_driver, crypto_driver);
    onion_client.run(command);
    
    
  }
  else{
    // Connect to network driver.
    std::shared_ptr<NetworkDriver> network_driver =
        std::make_shared<NetworkDriverImpl>();
    if (command == "listen") {
      network_driver->listen(port);
    } else if (command == "connect") {
      if (onion_mode) network_driver->connect(address, port + 1000);
      else network_driver->connect(address, port);
    } else {
      throw std::runtime_error("Error: got invalid client command.");
    }
    // Create client then run network, crypto, and cli.
    Client client = Client(network_driver, crypto_driver);
    client.run(command);
  }

  // std::thread client_thread([&client, &command](){ client.run(command); });

  //Creating one intermediate onion client
  // if (onion_mode && command == "listen"){
  //   std::shared_ptr<NetworkDriver> onion_network_driver1 =
  //     std::make_shared<NetworkDriverImpl>();
  //   std::shared_ptr<NetworkDriver> onion_network_driver2 =
  //     std::make_shared<NetworkDriverImpl>();
  //   onion_network_driver1->connect(address, port);
  //   onion_network_driver2->listen(port + 1);
  //   OnionClient onion_client = OnionClient(onion_network_driver1, onion_network_driver2, crypto_driver);

  //   onion_client.run(command);

    // std::thread onion_client_thread([&onion_client, &command](){ onion_client.run(command); });
    // client_thread.join();
    // onion_client_thread.join();
  // }
  // else {
  //   client_thread.join();
  // }
  return 0;
}
