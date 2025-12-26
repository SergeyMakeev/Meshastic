#!/usr/bin/env python3
"""
Meshastic - A simple yet powerful Meshtastic text mode client
A terminal-based client for Meshtastic mesh networking devices

This client connects to Meshtastic devices via USB/serial connection.
It uses the SerialInterface from the meshtastic library to communicate
directly with your device through a serial port.
"""

import sys
import time
import threading
import argparse
from datetime import datetime
from typing import Optional, List, Dict
import json
import os

try:
    import meshtastic
    from meshtastic.serial_interface import SerialInterface
    from meshtastic import portnums_pb2, mesh_pb2
except ImportError:
    print("Error: meshtastic library not found. Install it with: pip install meshtastic")
    sys.exit(1)

# Import serial tools for port listing (meshtastic includes pyserial)
try:
    import serial
    from serial.tools import list_ports
except ImportError:
    try:
        import serial
        import serial.tools.list_ports as list_ports
    except ImportError:
        serial = None
        list_ports = None


class MeshasticClient:
    """Main client class for Meshtastic terminal interface"""
    
    def __init__(self, port: Optional[str] = None, history_file: str = "meshastic_history.json"):
        self.port = port
        self.interface: Optional[SerialInterface] = None
        self.running = False
        self.history_file = history_file
        self.message_history: List[Dict] = []
        self.receive_thread: Optional[threading.Thread] = None
        
    def load_history(self):
        """Load message history from file"""
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'r') as f:
                    self.message_history = json.load(f)
            except Exception as e:
                print(f"Warning: Could not load history: {e}")
                self.message_history = []
    
    def save_history(self):
        """Save message history to file"""
        try:
            with open(self.history_file, 'w') as f:
                json.dump(self.message_history, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save history: {e}")
    
    def add_to_history(self, message: Dict):
        """Add message to history"""
        self.message_history.append(message)
        # Keep only last 1000 messages
        if len(self.message_history) > 1000:
            self.message_history = self.message_history[-1000:]
        self.save_history()
    
    def list_serial_ports(self):
        """List available serial ports"""
        try:
            if list_ports is None:
                print("Serial port listing not available. Install pyserial: pip install pyserial")
                return []
            
            ports = list_ports.comports()
            if not ports:
                print("No serial ports found")
                return []
            
            print("\n=== Available Serial Ports ===")
            port_list = []
            for port in ports:
                port_info = f"{port.device} - {port.description}"
                if port.manufacturer:
                    port_info += f" ({port.manufacturer})"
                print(f"  {port_info}")
                port_list.append(port.device)
            print()
            return port_list
        except Exception as e:
            print(f"Error listing serial ports: {e}")
            return []
    
    def try_connect_port(self, port: str) -> bool:
        """Try to connect to a specific serial port"""
        test_interface = None
        try:
            print(f"  Trying {port}...")
            # Try to create the interface - this might fail if port is in use or not accessible
            test_interface = SerialInterface(devPath=port)
            time.sleep(1.0)  # Give it time to initialize and detect the device
            
            # Try to get node info to verify it's a Meshtastic device
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    node_info = test_interface.getMyNodeInfo()
                    if node_info:
                        # Success! This is a Meshtastic device
                        self.interface = test_interface
                        return True
                    break
                except AttributeError as e:
                    # Device might need more time, or it's not a Meshtastic device
                    error_str = str(e)
                    if 'myInfo' in error_str or 'nodesByNum' in error_str:
                        # This might be a non-Meshtastic device or device not ready
                        if attempt < max_retries - 1:
                            print(f"    Device on {port} not ready yet, retrying...")
                            time.sleep(1.0)
                            continue
                        else:
                            # Not a Meshtastic device or not responding
                            print(f"    Port {port} opened but device didn't respond as Meshtastic device")
                            if test_interface:
                                try:
                                    test_interface.close()
                                except:
                                    pass
                            return False
                    else:
                        print(f"    Port {port} error: {e}")
                        if test_interface:
                            try:
                                test_interface.close()
                            except:
                                pass
                        return False
                except Exception as e:
                    # Some other error
                    print(f"    Port {port} error: {e}")
                    if test_interface:
                        try:
                            test_interface.close()
                        except:
                            pass
                    return False
            return False
        except serial.SerialException as e:
            # Port might be in use, locked, or not accessible
            error_msg = str(e).lower()
            if 'access is denied' in error_msg or 'permission' in error_msg or 'in use' in error_msg:
                print(f"    Port {port} is in use by another program")
                print(f"      - Close the other program using {port} and try again")
                print(f"      - Or wait for the other program to release the port")
            elif 'could not open port' in error_msg:
                print(f"    Port {port} could not be opened")
            else:
                print(f"    Port {port} error: {e}")
            return False
        except Exception as e:
            # Other connection errors
            error_msg = str(e)
            if "No Meshtastic device" in error_msg:
                # Not a Meshtastic device on this port
                print(f"    Port {port}: {error_msg}")
                return False
            # Print the error for debugging
            print(f"    Port {port} connection error: {e}")
            return False
    
    def connect(self) -> bool:
        """Connect to Meshtastic device via serial port"""
        try:
            if self.port:
                print(f"Connecting to Meshtastic device via serial port: {self.port}...")
                # Connect to specified serial port
                self.interface = SerialInterface(devPath=self.port)
                # Give it time to initialize
                time.sleep(1.0)
            else:
                print("Connecting to Meshtastic device via serial port (auto-detecting)...")
                # First try SerialInterface's built-in auto-detection
                try:
                    self.interface = SerialInterface()
                    # Give it a moment
                    time.sleep(0.5)
                    # Quick test to see if it worked
                    try:
                        test_info = self.interface.getMyNodeInfo()
                        if test_info:
                            # Success with auto-detection
                            pass
                        else:
                            raise Exception("Auto-detection found device but couldn't get info")
                    except AttributeError:
                        # Auto-detection likely fell back to TCP or failed
                        if self.interface:
                            try:
                                self.interface.close()
                            except:
                                pass
                        self.interface = None
                        raise Exception("Auto-detection failed")
                except Exception:
                    # Auto-detection failed, try all available ports
                    print("  Auto-detection didn't find device, trying available ports...")
                    if list_ports:
                        available_ports = [port.device for port in list_ports.comports()]
                        if available_ports:
                            for port in available_ports:
                                if self.try_connect_port(port):
                                    print(f"  [OK] Found Meshtastic device on {port}")
                                    break
                            else:
                                # None of the ports worked
                                raise Exception("No Meshtastic device found on any available port")
                        else:
                            raise Exception("No serial ports available")
                    else:
                        raise Exception("Cannot list ports - please specify port with -p option")
            
            # Wait a moment for the interface to initialize
            time.sleep(0.5)
            
            # Get device info to verify connection (with retry for initialization)
            max_retries = 3
            node_info = None
            last_error = None
            
            for attempt in range(max_retries):
                try:
                    node_info = self.interface.getMyNodeInfo()
                    break
                except AttributeError as e:
                    # Interface might not be fully initialized yet, or it's a TCP connection
                    last_error = e
                    error_str = str(e)
                    
                    # Check if this is the TCP fallback issue
                    if 'myInfo' in error_str or 'nodesByNum' in error_str:
                        # This often happens when SerialInterface falls back to TCP
                        # Check if we can detect TCP connection
                        if hasattr(self.interface, 'stream'):
                            stream_type = str(type(self.interface.stream))
                            if 'socket' in stream_type.lower() or 'tcp' in stream_type.lower():
                                raise Exception("TCP connection detected. This client requires a serial connection.")
                        
                        # Wait and retry - might just need more time
                        if attempt < max_retries - 1:
                            time.sleep(1.0)
                            continue
                        else:
                            # Last attempt failed - likely no serial device
                            raise Exception("No serial Meshtastic device found. Please connect your device via USB.")
                    else:
                        # Different AttributeError
                        if attempt < max_retries - 1:
                            time.sleep(0.5)
                            continue
                        else:
                            raise
                except Exception as e:
                    last_error = e
                    if attempt < max_retries - 1:
                        time.sleep(0.5)
                        continue
                    else:
                        raise
            
            if not node_info:
                print("[ERROR] Failed to get device information. Device may not be ready.")
                if last_error:
                    print(f"  Error: {last_error}")
                return False
            
            device_name = node_info.get('user', {}).get('longName', 'Unknown')
            node_id = node_info.get('num', 'Unknown')
            
            print(f"[OK] Connected via serial to device: {device_name}")
            print(f"  Node ID: {node_id}")
            
            # Get the actual serial port being used
            if hasattr(self.interface, 'port') and self.interface.port:
                print(f"  Serial Port: {self.interface.port}")
            elif hasattr(self.interface, 'stream') and hasattr(self.interface.stream, 'port'):
                print(f"  Serial Port: {self.interface.stream.port}")
            
            # Set up message callback - try different API methods
            # Note: Some versions of meshtastic may not support callbacks
            # The client will still work for sending messages
            callback_available = False
            try:
                if hasattr(self.interface, 'subscribe'):
                    try:
                        self.interface.subscribe(self.on_receive)
                        callback_available = True
                    except AttributeError:
                        # Method doesn't exist in this version
                        pass
                    except Exception:
                        # Some other error, but connection is still good
                        pass
                
                if not callback_available and hasattr(self.interface, 'setOnReceive'):
                    try:
                        self.interface.setOnReceive(self.on_receive)
                        callback_available = True
                    except:
                        pass
                
                if not callback_available and hasattr(self.interface, 'onReceive'):
                    try:
                        self.interface.onReceive = self.on_receive
                        callback_available = True
                    except:
                        pass
            except Exception:
                # Any callback setup error is non-fatal
                pass
            
            if not callback_available:
                print("  Note: Real-time message callbacks not available")
                print("  You can still send messages successfully")
            
            self.running = True
            return True
        except Exception as e:
            error_msg = str(e)
            
            # Check for serial-specific errors
            if serial and isinstance(e, serial.SerialException):
                print(f"[ERROR] Serial connection failed: {e}")
                print("  Make sure:")
                print("    - Your Meshtastic device is connected via USB")
                print("    - The device is not being used by another program")
                print("    - You have permission to access the serial port")
                if not self.port:
                    print("  Try specifying the port manually with -p option")
                    print("  Use --list-ports to see available serial ports")
            elif "TCP connection detected" in error_msg:
                print("[ERROR] TCP connection detected. This client requires a serial connection.")
                print("  The Meshtastic library tried to connect via TCP because no serial device was found.")
                print("  Make sure:")
                print("    - Your Meshtastic device is connected via USB")
                print("    - The device is powered on")
                print("    - Use --list-ports to see available serial ports")
                print("    - Try specifying the port manually with -p option")
            elif "No serial Meshtastic device" in error_msg or "No Meshtastic device" in error_msg or "No Meshtastic device found on any available port" in error_msg:
                print("[ERROR] No Meshtastic device found on serial ports")
                print("  Possible issues:")
                print("    - Port is in use by another program (close it first)")
                print("    - Device is not connected via USB")
                print("    - Device is not powered on")
                print("    - Device is not a Meshtastic device")
                print("  Solutions:")
                print("    - Close any other programs using the serial port (COM1)")
                print("    - Wait a few seconds and try again")
                print("    - Use --list-ports to see available serial ports")
                print("    - Specify the port manually: python meshastic_client.py -p COM1")
            elif "subscribe" in error_msg.lower():
                # Connection succeeded but callback setup failed - this is OK
                print("  Note: Message callbacks not available in this meshtastic version")
                print("  You can still send messages, but receiving may be limited")
                # Connection is actually successful, so don't return False
                # Just continue without callbacks
            elif "AttributeError" in error_msg or "myInfo" in error_msg or "nodesByNum" in error_msg:
                print("[ERROR] Device connection failed - no serial device found or device not ready")
                print("  This usually means:")
                print("    - No Meshtastic device is connected via USB/serial")
                print("    - The device is not powered on")
                print("    - Another program is using the device")
                print("  Try:")
                print("    - Use --list-ports to see available serial ports")
                print("    - Unplugging and replugging the device")
                print("    - Specifying the port manually with -p option")
            else:
                print(f"[ERROR] Connection failed: {e}")
                if "device" in error_msg.lower() or "serial" in error_msg.lower():
                    print("  Make sure your Meshtastic device is connected via USB and powered on")
                    print("  Use --list-ports to see available serial ports")
            
            # Clean up on failure
            if self.interface:
                try:
                    self.interface.close()
                except:
                    pass
                self.interface = None
            
            return False
    
    def on_receive(self, packet, interface):
        """Callback for received messages"""
        try:
            # Handle different packet formats
            decoded = None
            if isinstance(packet, dict):
                decoded = packet.get('decoded')
            elif hasattr(packet, 'decoded'):
                decoded = packet.decoded
            
            if decoded:
                # Check if it's a text message
                portnum = None
                if isinstance(decoded, dict):
                    portnum = decoded.get('portnum')
                elif hasattr(decoded, 'portnum'):
                    portnum = decoded.portnum
                
                # TEXT_MESSAGE_APP is typically 1
                if portnum == portnums_pb2.TEXT_MESSAGE_APP or portnum == 1:
                    # Extract text
                    text = ''
                    if isinstance(decoded, dict):
                        text = decoded.get('text', '')
                    elif hasattr(decoded, 'text'):
                        text = decoded.text
                    
                    # Extract sender info
                    from_id = 'Unknown'
                    from_name = 'Unknown'
                    if isinstance(packet, dict):
                        from_id = packet.get('fromId', packet.get('from', 'Unknown'))
                        # Try to get sender name from nodes
                        if self.interface and hasattr(self.interface, 'nodes'):
                            nodes = self.interface.nodes
                            if from_id in nodes:
                                user = nodes[from_id].get('user', {})
                                from_name = user.get('longName', user.get('shortName', str(from_id)))
                            else:
                                from_name = str(from_id)
                    elif hasattr(packet, 'fromId'):
                        from_id = packet.fromId
                        from_name = str(from_id)
                    
                    if text:
                        timestamp = datetime.now().isoformat()
                        
                        message = {
                            'timestamp': timestamp,
                            'from_id': str(from_id),
                            'from_name': from_name,
                            'text': text
                        }
                        
                        self.add_to_history(message)
                        
                        # Display message
                        print(f"\n[{timestamp}] {from_name} ({from_id}): {text}")
                        print("> ", end='', flush=True)
        except Exception as e:
            # Silently handle errors to avoid disrupting the interface
            pass
    
    def start_receive_thread(self):
        """Start background thread for receiving messages"""
        # The subscribe callback handles receiving, so we just need to keep the interface alive
        pass
    
    def send_message(self, text: str, destination_id: Optional[int] = None, skip_confirmation: bool = False) -> bool:
        """Send a text message (broadcast or private)"""
        if not self.interface:
            print("Error: Not connected to device")
            return False
        
        try:
            if destination_id:
                # Private message - no confirmation needed
                self.interface.sendText(text, destinationId=destination_id)
                # Try to get node name for display
                node_name = f"Node {destination_id}"
                nodes = self.get_node_info()
                if nodes:
                    for node_id, node in nodes.items():
                        if str(node.get('num', node_id)) == str(destination_id):
                            user = node.get('user', {})
                            node_name = user.get('longName', user.get('shortName', f"Node {destination_id}"))
                            break
                print(f"[OK] Private message sent to {node_name} ({destination_id}): {text}")
            else:
                # Broadcast message - require confirmation
                if not skip_confirmation:
                    print(f"\nBroadcast message to all nodes: {text}")
                    confirm = input("Send broadcast message? (yes/no): ").strip().lower()
                    if confirm not in ['yes', 'y']:
                        print("Broadcast message cancelled.")
                        return False
                
                self.interface.sendText(text)
                print(f"[OK] Broadcast message sent: {text}")
            
            timestamp = datetime.now().isoformat()
            message = {
                'timestamp': timestamp,
                'from_id': 'me',
                'from_name': 'Me',
                'text': text,
                'to_id': str(destination_id) if destination_id else 'broadcast'
            }
            self.add_to_history(message)
            return True
        except Exception as e:
            print(f"[ERROR] Failed to send message: {e}")
            return False
    
    def send_private_message(self, node_id: str, text: str) -> bool:
        """Send a private message to a specific node"""
        try:
            # Try to convert node_id to integer
            destination_id = int(node_id)
            return self.send_message(text, destination_id=destination_id)
        except ValueError:
            print(f"[ERROR] Invalid node ID: {node_id}. Node ID must be a number.")
            print("  Use /nodes to see available node IDs")
            return False
    
    def set_node_name(self, long_name: str, short_name: str) -> bool:
        """Set the node's long and short name"""
        if not self.interface:
            print("[ERROR] Not connected to device")
            return False
        
        # Validate short name length (must be 4 characters or less)
        if len(short_name) > 4:
            print(f"[ERROR] Short name must be 4 characters or less. Got: {len(short_name)} characters")
            return False
        
        if len(long_name) == 0:
            print("[ERROR] Long name cannot be empty")
            return False
        
        try:
            # Use setOwner to set the node name
            if hasattr(self.interface, 'localNode'):
                self.interface.localNode.setOwner(long_name=long_name, short_name=short_name)
            elif hasattr(self.interface, 'setOwner'):
                self.interface.setOwner(long_name=long_name, short_name=short_name)
            else:
                print("[ERROR] Cannot set node name - API not available in this meshtastic version")
                return False
            
            print(f"[OK] Node name updated:")
            print(f"  Long Name: {long_name}")
            print(f"  Short Name: {short_name}")
            print("  Note: Device may need to reboot for changes to take full effect")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to set node name: {e}")
            return False
    
    def reboot_device(self, delay_seconds: int = 10) -> bool:
        """Reboot the Meshtastic device"""
        if not self.interface:
            print("[ERROR] Not connected to device")
            return False
        
        try:
            # Get the local node
            local_node = None
            if hasattr(self.interface, 'localNode'):
                local_node = self.interface.localNode
            elif hasattr(self.interface, 'getNode'):
                local_node = self.interface.getNode()
            else:
                print("[ERROR] Cannot reboot device - API not available in this meshtastic version")
                return False
            
            if local_node and hasattr(local_node, 'reboot'):
                print(f"Rebooting device in {delay_seconds} seconds...")
                local_node.reboot(secs=delay_seconds)
                print(f"[OK] Reboot command sent. Device will reboot in {delay_seconds} seconds.")
                return True
            else:
                print("[ERROR] Reboot method not available")
                return False
        except Exception as e:
            print(f"[ERROR] Failed to reboot device: {e}")
            return False
    
    def get_node_info(self) -> Dict:
        """Get information about connected nodes"""
        if not self.interface:
            return {}
        
        try:
            nodes = self.interface.nodes
            return nodes
        except Exception as e:
            print(f"Error getting node info: {e}")
            return {}
    
    def print_node_data(self, data, indent=0, prefix=""):
        """Recursively print all node data"""
        indent_str = "  " * indent
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    print(f"{indent_str}{prefix}{key}:")
                    self.print_node_data(value, indent + 1)
                else:
                    print(f"{indent_str}{prefix}{key}: {value}")
        elif isinstance(data, list):
            for i, item in enumerate(data):
                print(f"{indent_str}{prefix}[{i}]:")
                self.print_node_data(item, indent + 1)
        else:
            print(f"{indent_str}{prefix}{data}")
    
    def show_nodes(self):
        """Display connected nodes with all available information"""
        nodes = self.get_node_info()
        if not nodes:
            print("No node information available")
            return
        
        print("\n=== Connected Nodes (All Information) ===")
        print("  (Use /pm <node_id> <message> to send private message)")
        print()
        for node_id, node in nodes.items():
            num = node.get('num', node_id)
            user = node.get('user', {})
            long_name = user.get('longName', 'Unknown')
            short_name = user.get('shortName', 'Unknown')
            
            print(f"--- Node ID: {num} ({long_name} / {short_name}) ---")
            print()
            
            # Print all available node information
            self.print_node_data(node, indent=0)
            print()
    
    def show_history(self, limit: int = 20):
        """Display recent message history"""
        if not self.message_history:
            print("No message history")
            return
        
        print(f"\n=== Recent Messages (last {limit}) ===")
        for msg in self.message_history[-limit:]:
            timestamp = msg.get('timestamp', 'Unknown')
            from_name = msg.get('from_name', 'Unknown')
            text = msg.get('text', '')
            to_id = msg.get('to_id', '')
            
            # Show if it was a private message
            if to_id and to_id != 'broadcast':
                            print(f"[{timestamp}] {from_name} -> Node {to_id}: {text}")
            else:
                print(f"[{timestamp}] {from_name}: {text}")
        print()
    
    def show_status(self):
        """Display device status"""
        if not self.interface:
            print("Not connected")
            return
        
        try:
            node_info = self.interface.getMyNodeInfo()
            print("\n=== Device Status ===")
            print(f"Connection Type: Serial")
            if hasattr(self.interface, 'port') and self.interface.port:
                print(f"Serial Port: {self.interface.port}")
            print(f"Node ID: {node_info.get('num', 'Unknown')}")
            user = node_info.get('user', {})
            print(f"Long Name: {user.get('longName', 'Unknown')}")
            print(f"Short Name: {user.get('shortName', 'Unknown')}")
            
            # Get radio config
            radio = node_info.get('radio', {})
            if radio:
                print(f"Radio Config: {radio}")
            
            print()
        except Exception as e:
            print(f"Error getting status: {e}")
    
    def interactive_mode(self):
        """Run interactive terminal mode"""
        if not self.connect():
            return
        
        self.load_history()
        print("\n=== Meshastic Client (Serial Connection) ===")
        print("Commands:")
        print("  /help     - Show this help")
        print("  /status   - Show device status")
        print("  /nodes    - List connected nodes")
        print("  /pm       - Send private message: /pm <node_id> <message>")
        print("  /setname  - Set node name: /setname <long_name> <short_name>")
        print("  /reboot   - Reboot the device: /reboot [delay_seconds]")
        print("  /history  - Show message history")
        print("  /clear    - Clear screen")
        print("  /quit     - Exit client")
        print("\nType a message to send (broadcast), or use commands above.")
        print("Use /pm <node_id> <message> to send a private message.")
        print("Use /setname <long_name> <short_name> to change your node name.")
        print("Use /reboot [delay] to reboot the device (default: 10 seconds).\n")
        
        try:
            while self.running:
                try:
                    user_input = input("> ").strip()
                    
                    if not user_input:
                        continue
                    
                    # Handle commands
                    if user_input.startswith('/'):
                        cmd = user_input.lower()
                        if cmd == '/quit' or cmd == '/exit':
                            break
                        elif cmd == '/help':
                            print("\nCommands:")
                            print("  /help     - Show this help")
                            print("  /status   - Show device status")
                            print("  /nodes    - List connected nodes")
                            print("  /pm       - Send private message: /pm <node_id> <message>")
                            print("  /setname  - Set node name: /setname <long_name> <short_name>")
                            print("  /reboot   - Reboot the device: /reboot [delay_seconds]")
                            print("  /history  - Show message history")
                            print("  /clear    - Clear screen")
                            print("  /quit     - Exit client")
                            print()
                        elif cmd == '/status':
                            self.show_status()
                        elif cmd == '/nodes':
                            self.show_nodes()
                        elif cmd.startswith('/pm ') or cmd.startswith('/private '):
                            # Parse private message command: /pm <node_id> <message>
                            parts = user_input.split(' ', 2)
                            if len(parts) < 3:
                                print("Usage: /pm <node_id> <message>")
                                print("Example: /pm 1234567890 Hello there!")
                                print("Use /nodes to see available node IDs")
                            else:
                                node_id = parts[1]
                                message = parts[2]
                                self.send_private_message(node_id, message)
                        elif cmd.startswith('/setname '):
                            # Parse setname command: /setname <long_name> <short_name>
                            parts = user_input.split(' ', 2)
                            if len(parts) < 3:
                                print("Usage: /setname <long_name> <short_name>")
                                print("Example: /setname My Device Name MDN")
                                print("Note: Short name must be 4 characters or less")
                            else:
                                long_name = parts[1]
                                short_name = parts[2]
                                self.set_node_name(long_name, short_name)
                        elif cmd.startswith('/reboot'):
                            # Parse reboot command: /reboot [delay_seconds]
                            parts = user_input.split()
                            delay = 10  # Default delay
                            if len(parts) > 1:
                                try:
                                    delay = int(parts[1])
                                    if delay < 0:
                                        print("[ERROR] Delay must be 0 or greater")
                                        continue
                                except ValueError:
                                    print("[ERROR] Invalid delay value. Must be a number.")
                                    print("Usage: /reboot [delay_seconds]")
                                    print("Example: /reboot 5")
                                    continue
                            
                            # Confirm reboot
                            print(f"Device will reboot in {delay} seconds.")
                            confirm = input("Confirm reboot? (yes/no): ").strip().lower()
                            if confirm in ['yes', 'y']:
                                self.reboot_device(delay)
                            else:
                                print("Reboot cancelled.")
                        elif cmd == '/history':
                            self.show_history()
                        elif cmd == '/clear':
                            os.system('cls' if os.name == 'nt' else 'clear')
                        else:
                            print(f"Unknown command: {user_input}. Type /help for help.")
                    else:
                        # Send message
                        self.send_message(user_input)
                
                except KeyboardInterrupt:
                    print("\nInterrupted. Use /quit to exit.")
                except EOFError:
                    break
        finally:
            self.disconnect()
    
    def disconnect(self):
        """Disconnect from device"""
        self.running = False
        if self.interface:
            try:
                self.interface.close()
                print("Disconnected from device")
            except:
                pass


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Meshastic - A simple yet powerful Meshtastic text mode client',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Interactive mode with auto-detected serial device
  %(prog)s -p COM3            # Connect to device on COM3 (Windows)
  %(prog)s -p /dev/ttyUSB0    # Connect to device on /dev/ttyUSB0 (Linux)
  %(prog)s -s "Hello World"   # Send a broadcast message via serial and exit
  %(prog)s --pm 1234567890 "Hi!"  # Send a private message to node 1234567890
  %(prog)s --setname "My Device" "MD"  # Set node name
  %(prog)s --reboot 5          # Reboot device in 5 seconds
  %(prog)s --status           # Show device status and exit
  %(prog)s --list-ports       # List available serial ports
        """
    )
    
    parser.add_argument('-p', '--port', help='Serial port (e.g., COM3 or /dev/ttyUSB0)')
    parser.add_argument('-s', '--send', help='Send a broadcast message and exit')
    parser.add_argument('--pm', nargs=2, metavar=('NODE_ID', 'MESSAGE'), 
                       help='Send a private message: --pm <node_id> <message>')
    parser.add_argument('--setname', nargs=2, metavar=('LONG_NAME', 'SHORT_NAME'),
                       help='Set node name: --setname <long_name> <short_name>')
    parser.add_argument('--reboot', type=int, metavar='DELAY', nargs='?', const=10,
                       help='Reboot the device: --reboot [delay_seconds] (default: 10)')
    parser.add_argument('--status', action='store_true', help='Show device status and exit')
    parser.add_argument('--nodes', action='store_true', help='List connected nodes and exit')
    parser.add_argument('--history', action='store_true', help='Show message history and exit')
    parser.add_argument('--list-ports', action='store_true', help='List available serial ports and exit')
    parser.add_argument('--history-file', default='meshastic_history.json', 
                       help='File to store message history (default: meshastic_history.json)')
    
    args = parser.parse_args()
    
    client = MeshasticClient(port=args.port, history_file=args.history_file)
    
    # Handle list ports command (doesn't need connection)
    if args.list_ports:
        client.list_serial_ports()
        sys.exit(0)
    
    # Handle non-interactive commands
    if args.status or args.nodes or args.history or args.send or args.pm or args.setname or args.reboot is not None:
        if not client.connect():
            sys.exit(1)
        
        client.load_history()
        
        if args.status:
            client.show_status()
        elif args.nodes:
            client.show_nodes()
        elif args.history:
            client.show_history()
        elif args.pm:
            node_id, message = args.pm
            client.send_private_message(node_id, message)
        elif args.setname:
            long_name, short_name = args.setname
            client.set_node_name(long_name, short_name)
        elif args.reboot is not None:
            delay = args.reboot if args.reboot > 0 else 10
            client.reboot_device(delay)
        elif args.send:
            # Command-line send - skip confirmation for automation
            client.send_message(args.send, skip_confirmation=True)
        
        client.disconnect()
    else:
        # Interactive mode
        client.interactive_mode()


if __name__ == '__main__':
    main()

