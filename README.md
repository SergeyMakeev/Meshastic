# Meshastic - Meshtastic Terminal Client

A simple yet powerful text mode client for Meshtastic mesh networking devices, designed to work everywhere through the terminal.

## Features

- **Simple & Fast**: Lightweight terminal interface
- **Real-time Messaging**: Send and receive messages instantly via serial connection
- **Message History**: Automatic message logging with JSON storage
- **End-to-End Encryption**: Encrypt private messages with per-node keys
- **Serial Connection**: Direct USB/serial connection to Meshtastic device
- **Auto-detection**: Automatically finds your Meshtastic device on serial ports
- **Cross-platform**: Works on Windows, Linux, and macOS
- **Interactive Mode**: Full-featured interactive terminal interface
- **Port Listing**: List available serial ports to find your device
- **Node Discovery**: Find nodes by name with wildcard support
- **Node Information**: View hop count, last seen time, and position data

## Installation

1. **Install Python 3.7+** (if not already installed)

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
   
   Or directly:
   ```bash
   pip install meshtastic pypubsub cryptography
   ```
   
   **Note:** The `cryptography` library is required for encryption features. If you don't need encryption, you can skip it, but encryption features will be unavailable.

3. **Make the script executable** (Linux/macOS):
   ```bash
   chmod +x meshastic_client.py
   ```

## Usage

### Interactive Mode

The default mode provides a full interactive terminal interface:

```bash
python meshastic_client.py
```

Or on Linux/macOS:
```bash
./meshastic_client.py
```

**Interactive Commands:**
- `/help` - Show help and available commands
- `/status` - Show device status and connection information
- `/nodes [pattern]` - List connected nodes (supports wildcard patterns)
- `/resolve <pattern>` - Find node IDs by name pattern (supports wildcards)
- `/pm <node_id_or_name> <message>` - Send a private message (supports node ID or exact name match)
- `/broadcast <message>` - Send a broadcast message to all nodes
- `/setkey <node_id_or_name> <password>` - Set encryption key for private messages with a node
- `/setname <long_name> <short_name>` - Set your device's name
- `/reboot [delay]` - Reboot the device (optional delay in seconds)
- `/history` - Show message history
- `/clear` - Clear screen
- `/quit` - Exit client

**Sending Messages:**
- Use `/broadcast <message>` to send a message to all nodes
- Use `/pm <node_id_or_name> <message>` to send a private message
  - Example: `/pm 1234567890 Hello, this is private!`
  - Example: `/pm joker13 Hello!` (uses exact name match)

**Finding Nodes:**
- Use `/nodes` to see all available nodes with hop count and last seen time
- Use `/nodes *pattern*` to filter nodes by name pattern
- Use `/resolve <pattern>` to find node IDs by name (supports wildcards like `*my_node*`)

**Encryption:**
- Use `/setkey <node_id_or_name> <password>` to set an encryption key for a node
- Both parties must use the same password for encryption to work
- Private messages are automatically encrypted if a key is set
- Keys are stored in `meshastic_keys.json`

### Command Line Options

List available serial ports:
```bash
python meshastic_client.py --list-ports
```

Specify a serial port (if auto-detection doesn't work):

**Windows:**
```bash
python meshastic_client.py --port COM3
```

**Linux:**
```bash
python meshastic_client.py --port /dev/ttyUSB0
```

**macOS:**
```bash
python meshastic_client.py --port /dev/cu.usbserial-*
```

## Message History

Messages are automatically saved to `meshastic_history.json` in the current directory. The history file stores:
- Timestamp
- Sender information
- Message text
- Encryption status

## Encryption Keys

Encryption keys are stored in `meshastic_keys.json` in the current directory. Each node has its own encryption key:
- Keys are derived from passwords using PBKDF2
- Each node encrypts messages with its own key
- Recipients decrypt messages using the sender's key
- Both clients can share the same keys file for seamless communication

**Important:** For encryption to work, both parties must have the same key file or set the same password for each other's node ID.

## Examples

**Interactive session:**
```bash
$ python meshastic_client.py
Connecting to Meshtastic device...
Connected to device: My Mesh Node
  Node ID: 1234567890

=== Meshastic Client ===
Commands:
  /help     - Show this help
  /status   - Show device status
  /nodes    - List connected nodes: /nodes [pattern] (supports wildcards)
  /pm       - Send private message: /pm <node_id_or_name> <message>
  /resolve  - Resolve name to node ID: /resolve <pattern> (supports wildcards)
  /broadcast - Send broadcast message: /broadcast <message>
  /setkey   - Set encryption key for node: /setkey <node_id_or_name> <password>
  /history  - Show message history
  /clear    - Clear screen
  /quit     - Exit client

Use commands to send messages. Type /help for available commands.

> /nodes
--- Node ID: 1234567890 (My Mesh Node / MESH) [CURRENT DEVICE] ---
id: !a1b2c3d4
longName: My Mesh Node
shortName: MESH
hopsAway: 0
...

> /broadcast Hello, mesh network!
Message sent: Hello, mesh network!

[2024-01-15T10:30:45] Node123: Thanks for the message!

> /pm 9876543210 Hello, this is private!
Private message sent to node 9876543210

> /setkey 9876543210 mySecretPassword
[OK] Encryption key set for node 9876543210
  Private messages with this node will now be encrypted
  Make sure the other party uses the same password!

> /resolve *node*
  Node ID: 1234567890 - My Mesh Node (MESH) [CURRENT DEVICE]
  Node ID: 9876543210 - Another Node (AN)

> /quit
Disconnected from device
```

## Requirements

- Python 3.7 or higher
- Meshtastic device connected via USB/serial port
- `meshtastic` Python library (includes pyserial for serial communication)
- `pypubsub` library (for message reception)
- `cryptography` library (optional, for encryption features)

