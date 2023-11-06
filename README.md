# p2p-ethereum-handshake

This is a Rust application that performs a protocol-level handshake with a target Ethereum node.

## Platform Compatibility

Both the target node and the handshake code compile on Linux.

## Code Independence

- The solution does not depend on the code of the target node.

- The submitted code does not reuse entire preexisting handshake implementations such as libp2p_noise/XX.

## How It Works

The application initiates a TCP connection with a target node, then performs a handshake at the protocol level. This involves sending an initial handshake message, waiting for a response from the target node, and potentially sending a confirmation message.

## Getting Started

1. Clone the repository: `git clone https://github.com/mrozdolski/p2p-ethereum-handshake.git`
2. Navigate to the project directory: `cd p2p-ethereum-handshake`
3. Build the project: `cargo build`
4. Run the project: `cargo run [nodeID] [nodeIP] [port]`

## Instructions and verifying the handshake

To test and verify the handshake process, follow these steps:

1. Run the project with a target node's ID, IP, and port as arguments:
   
   ***Example HoleskyBootnode:*** 
   
   ```
   cargo run ac906289e4b7f12df423d654c5a962b6ebe5b3a74cc9e06292a85221f9a64a6f1cfdd6b714ed6dacef51578f92b34c60ee91e9ede9c7f8fadc4d347326d95e2b 146.190.13.128 30303
   ```
2. The program will output log messages as it performs the handshake. Look for a message indicating that the handshake has been completed successfully.
3. If the handshake fails, the program will output an error message. Check this message to see what went wrong.

**Example output:**

```
Connecting to node at: 146.190.13.128:30303
Connected to node ✅
Sent auth message to target node 👋

Connection established successfully 🤝

Hello message from target node:
Hello { protocol_version: 5, client_version: "Geth/v1.13.2-stable-dc34fe82/linux-amd64/go1.21.1", capabilities: [Capability { name: "eth", version: 67 }, Capability { name: "eth", version: 68 }, Capability { name: "les", version: 2 }, Capability { name: "les", version: 3 }, Capability { name: "les", version: 4 }, Capability { name: "snap", version: 1 }], port: 0, id: PublicKey(6f4aa6f92152a89262e0c94ca7b3e5ebb662a9c554d623f42df1b7e4896290ac2b5ed92673344ddcfaf8c7e9ede991ee604cb3928f5751efac6ded14b7d6fd1c) }
```


Please note that successful completion of the handshake is dependent on the target node's availability and its compatibility with the RLPx protocol. [List of available nodes](https://github.com/ethereum/go-ethereum/blob/master/params/bootnodes.go)