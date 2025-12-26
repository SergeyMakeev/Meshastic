# Meshastic - Meshtastic Terminal Client

A simple yet powerful text mode client for Meshtastic mesh networking devices, designed to work everywhere through the terminal.

## Features

- 🚀 **Simple & Fast**: Lightweight terminal interface
- 📡 **Real-time Messaging**: Send and receive messages instantly via serial connection
- 📜 **Message History**: Automatic message logging with JSON storage
- 🔌 **Serial Connection**: Direct USB/serial connection to Meshtastic device
- 🔍 **Auto-detection**: Automatically finds your Meshtastic device on serial ports
- 🌐 **Cross-platform**: Works on Windows, Linux, and macOS
- 💬 **Interactive Mode**: Full-featured interactive terminal interface
- 🎯 **Command Mode**: Send messages and get status from command line
- 📋 **Port Listing**: List available serial ports to find your device

## Installation

1. **Install Python 3.7+** (if not already installed)

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
   
   Or directly:
   ```bash
   pip install meshtastic
   ```

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
- Type any message and press Enter to send (broadcast)
- `/help` - Show help
- `/status` - Show device status
- `/nodes` - List connected nodes with their IDs
- `/pm <node_id> <message>` - Send a private message to a specific node
- `/history` - Show message history
- `/clear` - Clear screen
- `/quit` - Exit client

**Private Messages:**
To send a private message to a specific node:
1. Use `/nodes` to see available nodes and their IDs
2. Use `/pm <node_id> <message>` to send a private message
   Example: `/pm 1234567890 Hello, this is private!`

### Command Line Mode

Send a broadcast message and exit:
```bash
python meshastic_client.py -s "Hello, Meshtastic!"
```

Send a private message and exit:
```bash
python meshastic_client.py --pm 1234567890 "Hello, this is private!"
```

Show device status:
```bash
python meshastic_client.py --status
```

List connected nodes:
```bash
python meshastic_client.py --nodes
```

Show message history:
```bash
python meshastic_client.py --history
```

List available serial ports:
```bash
python meshastic_client.py --list-ports
```

### Specify Serial Port

If auto-detection doesn't work, specify the port manually:

**Windows:**
```bash
python meshastic_client.py -p COM3
```

**Linux:**
```bash
python meshastic_client.py -p /dev/ttyUSB0
```

**macOS:**
```bash
python meshastic_client.py -p /dev/cu.usbserial-*
```

## Message History

Messages are automatically saved to `meshastic_history.json` in the current directory. The history file stores:
- Timestamp
- Sender information
- Message text

You can change the history file location with `--history-file`:
```bash
python meshastic_client.py --history-file /path/to/history.json
```

## Examples

**Quick message:**
```bash
python meshastic_client.py -s "Status check: All good!"
```

**Interactive session:**
```bash
$ python meshastic_client.py
Connecting to Meshtastic device...
✓ Connected to device: My Mesh Node
  Node ID: 1234567890

=== Meshastic Client ===
Commands:
  /help     - Show this help
  /status   - Show device status
  /nodes    - List connected nodes
  /history  - Show message history
  /clear    - Clear screen
  /quit     - Exit client

Type a message to send, or use commands above.

> Hello, mesh network!
✓ Message sent: Hello, mesh network!

[2024-01-15T10:30:45] Node123: Thanks for the message!
> /status

=== Device Status ===
Node ID: 1234567890
Long Name: My Mesh Node
Short Name: MESH
> /quit
Disconnected from device
```

## Requirements

- Python 3.7 or higher
- Meshtastic device connected via USB/serial port
- `meshtastic` Python library (includes pyserial for serial communication)

## Troubleshooting

**Device not found:**
- Make sure your Meshtastic device is connected via USB/serial
- Use `--list-ports` to see available serial ports
- Try specifying the port manually with `-p`
- Check device permissions (Linux: add user to dialout group)
- Ensure the device is not being used by another program

**Permission denied (Linux):**
```bash
sudo usermod -a -G dialout $USER
# Then log out and log back in
```

**Import error:**
```bash
pip install --upgrade meshtastic
```

## License

This project is provided as-is for use with Meshtastic devices.

## Contributing

Feel free to submit issues and enhancement requests!

