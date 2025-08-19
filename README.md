# Quantum-Secure Onion Routing

This is an implementation of QUACK, a quantum-safe secure communication system. To run our code, clear the build directory, and then use cmake and make build targets. Finally, use the command ./signal_app <listen | connect> <address> <port> to listen or connect to a secure channel.

We also have a prototype chained communication system that will eventually include layered onion encryptions. To access this, see the onion_mode branch of this repository. while using onion mode, you need to run the following commands:

./signal_app (listen | connect) (address) (port) onion

for an edge client, and 

./signal_app (listen | connect) (address1) (port1) (address2) (port2) onion

for a onion router.

Before each run of this, make sure to clear keys.JSON so that it only includes

{
  
  "num_keys" : 0

}

Have fun!
