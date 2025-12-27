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
import fnmatch
import base64
import hashlib
import uuid

try:
    import meshtastic
    from meshtastic.serial_interface import SerialInterface
    from meshtastic import portnums_pb2, mesh_pb2
    from pubsub import pub
except ImportError:
    print("Error: meshtastic library not found. Install it with: pip install meshtastic")
    print("Also ensure pubsub is installed: pip install pypubsub")
    sys.exit(1)

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    import base64
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False
    print("Warning: cryptography library not found. Encryption will not be available.")
    print("Install it with: pip install cryptography")

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
        self.keys_file = "meshastic_keys.json"
        self.encryption_keys: Dict[str, str] = {}  # node_id -> base64 encoded key
        self.load_encryption_keys()
        # File transfer state: file_id -> {filename, total_chunks, received_chunks: {chunk_num: data}, from_id, from_name}
        self.file_transfers: Dict[str, Dict] = {}
        # Long message transfer state: message_id -> {total_chunks, received_chunks: {chunk_num: data}, from_id, from_name, is_encrypted}
        self.message_transfers: Dict[str, Dict] = {}
        # Orphaned chunks: chunks received before header (keyed by file_id/message_id)
        self.orphaned_chunks: Dict[str, List[Dict]] = {}
        
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
    
    def load_encryption_keys(self):
        """Load encryption keys from file"""
        if os.path.exists(self.keys_file):
            try:
                with open(self.keys_file, 'r') as f:
                    self.encryption_keys = json.load(f)
            except Exception as e:
                print(f"Warning: Could not load encryption keys: {e}")
                self.encryption_keys = {}
    
    def save_encryption_keys(self):
        """Save encryption keys to file"""
        try:
            with open(self.keys_file, 'w') as f:
                json.dump(self.encryption_keys, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save encryption keys: {e}")
    
    def derive_key_from_password(self, password: str, salt: bytes = None) -> bytes:
        """Derive a Fernet key from a password using PBKDF2"""
        if salt is None:
            salt = b'meshastic_salt_2024'  # Fixed salt for consistency
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        # Derive 32 bytes and encode to base64 (Fernet key format)
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def get_encryption_key(self, node_id: str) -> Optional[bytes]:
        """Get encryption key for a node"""
        if not ENCRYPTION_AVAILABLE:
            return None
        
        node_id_str = str(node_id)
        if node_id_str in self.encryption_keys:
            try:
                key_str = self.encryption_keys[node_id_str]
                # Keys in JSON are base64 strings
                # Fernet keys are 44 characters when properly encoded
                # If key is longer (60 chars), it's double-encoded from old version
                if len(key_str) > 44:
                    # Double-encoded: decode once to get the actual Fernet key
                    try:
                        decoded = base64.urlsafe_b64decode(key_str.encode())
                        # decoded is now 44 bytes, which contains the base64-encoded key as a string
                        # Convert bytes to string, then back to bytes for Fernet
                        key_string = decoded.decode('utf-8')
                        return key_string.encode()
                    except Exception as e:
                        print(f"[DEBUG] Failed to decode double-encoded key for {node_id_str}: {e}")
                        return None
                else:
                    # Properly encoded (44 chars): just convert string to bytes
                    return key_str.encode()
            except Exception as e:
                print(f"[DEBUG] Error getting key for {node_id_str}: {e}")
                return None
        return None
    
    def set_encryption_key(self, node_id: str, password: str) -> bool:
        """Set encryption key for a node from a password"""
        if not ENCRYPTION_AVAILABLE:
            print("[ERROR] Encryption not available. Install cryptography: pip install cryptography")
            return False
        
        try:
            key = self.derive_key_from_password(password)
            # Store as string (Fernet keys are base64-encoded strings)
            key_str = key.decode()
            self.encryption_keys[str(node_id)] = key_str
            self.save_encryption_keys()
            return True
        except Exception as e:
            print(f"[ERROR] Failed to set encryption key: {e}")
            return False
    
    def encrypt_message(self, text: str, node_id: str = None) -> Optional[str]:
        """Encrypt a message using the sender's (our own) key"""
        if not ENCRYPTION_AVAILABLE:
            return text
        
        # Use our own node ID for encryption (each node encrypts with its own key)
        my_node_id = self.get_my_node_id()
        if my_node_id is None:
            return text  # Can't get our node ID, send unencrypted
        
        key = self.get_encryption_key(str(my_node_id))
        if key is None:
            return text  # No key set for our node, send unencrypted
        
        try:
            fernet = Fernet(key)
            encrypted = fernet.encrypt(text.encode('utf-8'))
            # Prefix with marker to indicate encryption
            return f"[ENCRYPTED]{base64.urlsafe_b64encode(encrypted).decode()}"
        except Exception as e:
            print(f"[WARN] Encryption failed for our node {my_node_id}: {e}, sending unencrypted")
            return text
    
    def decrypt_message(self, text: str, from_id: str) -> str:
        """Decrypt a message from a specific node using the sender's key"""
        if not ENCRYPTION_AVAILABLE:
            return text
        
        # Check if message is encrypted
        if not text.startswith("[ENCRYPTED]"):
            return text
        
        # Use the sender's key for decryption (each node decrypts with the sender's key)
        key = self.get_encryption_key(str(from_id))
        if key is None:
            return f"[ENCRYPTED_MESSAGE: No key available for node {from_id}]"
        
        try:
            encrypted_data = text[11:]  # Remove "[ENCRYPTED]" prefix
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
            fernet = Fernet(key)
            decrypted = fernet.decrypt(encrypted_bytes)
            return decrypted.decode('utf-8')
        except Exception as e:
            # Decryption failed - might be wrong key or corrupted data
            error_msg = str(e)
            if "InvalidToken" in error_msg or "Invalid key" in error_msg:
                return f"[DECRYPTION_FAILED: Wrong encryption key for node {from_id}. Make sure you have the correct key for this sender stored in your keys file.]"
            else:
                return f"[DECRYPTION_FAILED: {error_msg}]"
    
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
            
            # Get and display full port information
            port_info = self.get_port_info()
            print(f"  Serial Port: {port_info['full_name']}")
            
            # Set up message callback using pubsub (like the working example)
            try:
                pub.subscribe(self.on_receive, "meshtastic.receive")
                print("  [OK] Message callbacks enabled via pubsub")
                callback_available = True
            except Exception as e:
                print(f"  [WARN] Failed to set up message callbacks: {e}")
                callback_available = False
            
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
        """Callback for received messages using pubsub"""
        try:
            # Handle packet in dictionary format (like the working example)
            if not isinstance(packet, dict):
                return
            
            decoded = packet.get('decoded')
            if not decoded:
                return
            
            # Check if it's a text message
            portnum = decoded.get('portnum')
            
            # Handle both string and numeric portnum
            is_text_message = False
            if portnum == 'TEXT_MESSAGE_APP' or portnum == portnums_pb2.TEXT_MESSAGE_APP or portnum == 1:
                is_text_message = True
            
            if is_text_message:
                # Extract text from payload (like the working example)
                text = ''
                if 'payload' in decoded:
                    try:
                        text = decoded['payload'].decode('utf-8')
                    except (UnicodeDecodeError, AttributeError):
                        # Try as string if already decoded
                        text = str(decoded.get('payload', ''))
                elif 'text' in decoded:
                    text = decoded['text']
                
                if text:
                    # Extract sender info
                    from_id = packet.get('fromId', 'Unknown')
                    from_name = 'Unknown'
                    
                    # Try to get sender name and node ID from nodes
                    node_id_for_key = None
                    if self.interface and hasattr(self.interface, 'nodes'):
                        nodes = self.interface.nodes
                        if from_id in nodes:
                            node = nodes[from_id]
                            user = node.get('user', {})
                            from_name = user.get('longName', user.get('shortName', str(from_id)))
                            # Get the node ID (num) for key lookup
                            node_id_for_key = node.get('num', from_id)
                        else:
                            from_name = str(from_id)
                            node_id_for_key = from_id
                    else:
                        from_name = str(from_id)
                        node_id_for_key = from_id
                    
                    # Decrypt message if it's encrypted (use node ID for key lookup)
                    decrypted_text = self.decrypt_message(text, str(node_id_for_key))
                    is_encrypted = decrypted_text != text
                    
                    # Check if this is a file transfer message
                    if self._handle_file_chunk(decrypted_text, str(node_id_for_key), from_name):
                        # File message handled, don't display as regular message
                        print("> ", end='', flush=True)
                        return  # Exit early, file message already handled
                    
                    # Check if this is a long message chunk
                    if self._handle_message_chunk(decrypted_text, str(node_id_for_key), from_name):
                        # Long message chunk handled, don't display as regular message
                        print("> ", end='', flush=True)
                        return  # Exit early, message chunk already handled
                    
                    timestamp = datetime.now().isoformat()
                    
                    message = {
                        'timestamp': timestamp,
                        'from_id': str(from_id),
                        'from_name': from_name,
                        'text': decrypted_text,
                        'encrypted': is_encrypted
                    }
                    
                    # Check if we've already seen this message (avoid duplicates)
                    if not self._is_duplicate_message(message):
                        self.add_to_history(message)
                        
                        # Display message
                        enc_indicator = " [ENCRYPTED]" if is_encrypted else ""
                        print(f"\n[{timestamp}] {from_name} ({from_id}){enc_indicator}: {decrypted_text}")
                        print("> ", end='', flush=True)
        except KeyError:
            # Ignore KeyError silently (like the working example)
            pass
        except Exception as e:
            # Silently handle other errors
            pass
    
    def _is_duplicate_message(self, message: Dict) -> bool:
        """Check if we've already seen this message"""
        if not self.message_history:
            return False
        
        # Check last 10 messages for duplicates
        for existing in self.message_history[-10:]:
            if (existing.get('text') == message.get('text') and
                existing.get('from_id') == message.get('from_id') and
                existing.get('timestamp') == message.get('timestamp')):
                return True
        return False
    
    
    
    def _process_message_dict(self, msg: Dict):
        """Process a message dictionary"""
        try:
            text = msg.get('text', '')
            if not text:
                return
            
            from_id = msg.get('fromId', msg.get('from', 'Unknown'))
            from_name = 'Unknown'
            
            # Try to get sender name from nodes
            if self.interface and hasattr(self.interface, 'nodes'):
                nodes = self.interface.nodes
                if from_id in nodes:
                    user = nodes[from_id].get('user', {})
                    from_name = user.get('longName', user.get('shortName', str(from_id)))
                else:
                    from_name = str(from_id)
            
            timestamp = datetime.now().isoformat()
            
            message = {
                'timestamp': timestamp,
                'from_id': str(from_id),
                'from_name': from_name,
                'text': text
            }
            
            # Check if we've already seen this message
            if not self._is_duplicate_message(message):
                self.add_to_history(message)
                
                # Display message
                print(f"\n[{timestamp}] {from_name} ({from_id}): {text}")
                print("> ", end='', flush=True)
        except Exception:
            pass
    
    def _send_encrypted_private_message(self, text: str, destination_id: int) -> bool:
        """Send an encrypted private message to a specific node (reusable function)
        
        Args:
            text: Message text to send
            destination_id: Destination node ID
            
        Returns:
            True if sent successfully, False otherwise
        """
        if not self.interface:
            return False
        
        try:
            # Encrypt if key is available
            message_to_send = self.encrypt_message(text, str(destination_id))
            is_encrypted = message_to_send != text
            
            # Check message size
            message_size = len(message_to_send.encode('utf-8'))
            
            # Private message - use wantAck=True to ensure delivery
            # Try different API formats for compatibility
            try:
                # Try with wantAck parameter (recommended for private messages)
                self.interface.sendText(message_to_send, destinationId=destination_id, wantAck=True)
            except TypeError:
                # Fallback if wantAck is not supported
                try:
                    self.interface.sendText(message_to_send, destinationId=destination_id)
                except Exception as e:
                    # Try alternative API format
                    if hasattr(self.interface, 'sendData'):
                        # Some versions use sendData for private messages
                        from meshtastic import portnums_pb2
                        self.interface.sendData(message_to_send.encode('utf-8'), destinationId=destination_id, wantAck=True, portNum=portnums_pb2.TEXT_MESSAGE_APP)
                    else:
                        raise e
            except Exception as e:
                error_msg = str(e)
                if "too big" in error_msg.lower() or "payload" in error_msg.lower():
                    print(f"[ERROR] Failed to send private message: {error_msg}")
                    print(f"  Message size: {message_size} bytes (raw text: {len(text.encode('utf-8'))} bytes)")
                    print(f"  Encrypted: {is_encrypted}")
                else:
                    print(f"[ERROR] Failed to send private message: {error_msg}")
                return False
            
            return True
        except Exception as e:
            error_msg = str(e)
            if "too big" in error_msg.lower() or "payload" in error_msg.lower():
                message_size = len(message_to_send.encode('utf-8')) if 'message_to_send' in locals() else 0
                print(f"[ERROR] Failed to send private message: {error_msg}")
                print(f"  Message size: {message_size} bytes (raw text: {len(text.encode('utf-8'))} bytes)")
                print(f"  Encrypted: {is_encrypted if 'is_encrypted' in locals() else 'unknown'}")
            else:
                print(f"[ERROR] Failed to send private message: {error_msg}")
            return False
    
    def send_message(self, text: str, destination_id: Optional[int] = None, skip_confirmation: bool = False) -> bool:
        """Send a text message (broadcast or private)"""
        if not self.interface:
            print("Error: Not connected to device")
            return False
        
        try:
            if destination_id:
                # Private message - use reusable function
                is_encrypted = self.encrypt_message(text, str(destination_id)) != text
                success = self._send_encrypted_private_message(text, destination_id)
                
                if not success:
                    return False
                
                # Try to get node name for display
                node_name = f"Node {destination_id}"
                nodes = self.get_node_info()
                if nodes:
                    for node_id, node in nodes.items():
                        if str(node.get('num', node_id)) == str(destination_id):
                            user = node.get('user', {})
                            node_name = user.get('longName', user.get('shortName', f"Node {destination_id}"))
                            break
                
                enc_status = " [ENCRYPTED]" if is_encrypted else ""
                print(f"[OK] Private message sent to {node_name} ({destination_id}){enc_status}: {text}")
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
    
    def send_private_message(self, node_identifier: str, text: str) -> bool:
        """Send a private message to a specific node by ID or exact name match
        
        Args:
            node_identifier: Node ID (number) or exact node name (long name or short name)
            text: Message text to send
        """
        # Resolve node identifier to node ID
        destination_id = None
        try:
            destination_id = int(node_identifier)
        except ValueError:
            # Not a number, try to resolve as exact name match
            pass
        
        # Try to find exact name match (case-insensitive)
        nodes = self.get_node_info()
        if not nodes:
            print("[ERROR] No node information available")
            return False
        
        node_identifier_lower = node_identifier.lower()
        matches = []
        
        for node_id, node in nodes.items():
            num = node.get('num', node_id)
            user = node.get('user', {})
            long_name = user.get('longName', '')
            short_name = user.get('shortName', '')
            
            # Check for exact match (case-insensitive) against long name or short name
            if (long_name and long_name.lower() == node_identifier_lower) or \
               (short_name and short_name.lower() == node_identifier_lower):
                matches.append((num, long_name, short_name))
        
        if not matches:
            print(f"[ERROR] No nodes found with exact name: {node_identifier}")
            print("  Use /nodes to see available nodes")
            print("  Use /resolve <pattern> to find nodes by name pattern")
            return False
        
        if len(matches) > 1:
            print(f"[ERROR] Multiple nodes found with name '{node_identifier}':")
            for node_id, long_name, short_name in matches:
                name_display = long_name if long_name else short_name
                if not name_display:
                    name_display = f"Node {node_id}"
                print(f"  Node ID: {node_id} - {name_display} ({short_name if short_name else 'N/A'})")
            print("  Please use the node ID directly to avoid ambiguity")
            return False
        
        destination_id = matches[0][0]
        
        if not destination_id:
            print(f"[ERROR] Could not resolve node: {node_identifier}")
            return False
        
        # Check if message is too long for a single message
        # Meshtastic limit is around 240 bytes, but we need to account for encryption overhead
        # If message would be too long after encryption, split it into chunks
        raw_message_size = len(text.encode('utf-8'))
        
        # Estimate encrypted size (roughly 1.5x for encryption overhead)
        estimated_encrypted_size = int(raw_message_size * 1.5)
        
        # If message would exceed ~200 bytes after encryption, use chunking
        if estimated_encrypted_size > 200:
            return self._send_long_message(text, destination_id)
        else:
            # Regular short message
            return self.send_message(text, destination_id=destination_id)
    
    def _send_long_message(self, text: str, destination_id: int) -> bool:
        """Send a long message by encrypting first, then splitting into chunks
        
        Args:
            text: Message text to send
            destination_id: Destination node ID
            
        Returns:
            True if sent successfully, False otherwise
        """
        # Encrypt the entire message first (if encryption is enabled)
        my_node_id = self.get_my_node_id()
        if my_node_id is None:
            print("[ERROR] Cannot get our node ID for encryption")
            return False
        
        key = self.get_encryption_key(str(my_node_id))
        if key is None:
            print("[WARN] No encryption key set for our node, sending message unencrypted")
            encrypted_data = text.encode('utf-8')
            is_encrypted = False
        else:
            try:
                from cryptography.fernet import Fernet
                fernet = Fernet(key)
                encrypted_data = fernet.encrypt(text.encode('utf-8'))
                is_encrypted = True
            except Exception as e:
                print(f"[ERROR] Failed to encrypt message: {e}")
                return False
        
        # Base64 encode the encrypted data
        encrypted_base64 = base64.b64encode(encrypted_data).decode('utf-8')
        
        # Split encrypted data into chunks (stable chunk size - no encryption overhead per chunk)
        # Meshtastic messages have a limit around 240 bytes
        # We need room for: [MSGCHUNK:message_id:chunk_num:total_chunks:data]
        # Metadata is ~30-40 bytes, so we can use ~180 bytes for data
        chunk_size = 180
        total_chunks = (len(encrypted_base64) + chunk_size - 1) // chunk_size
        
        # Generate unique message ID (short)
        message_id = str(uuid.uuid4())[:8]
        
        print(f"[INFO] Sending long message ({len(text)} chars, {total_chunks} chunks) to node {destination_id}...")
        
        # Send message header
        # Format: [MSG:message_id:total_chunks:encrypted]
        is_encrypted_flag = "1" if is_encrypted else "0"
        header = f"[MSG:{message_id}:{total_chunks}:{is_encrypted_flag}]"
        if not self._send_encrypted_private_message(header, destination_id):
            print("[ERROR] Failed to send message header")
            return False
        
        # Send chunks (no encryption needed - data is already encrypted)
        for chunk_num in range(total_chunks):
            start = chunk_num * chunk_size
            end = start + chunk_size
            chunk_data = encrypted_base64[start:end]
            
            # Send chunk with metadata (no encryption - data is already encrypted)
            # Format: [MSGCHUNK:message_id:chunk_num:total_chunks:data]
            chunk_message = f"[MSGCHUNK:{message_id}:{chunk_num}:{total_chunks}:{chunk_data}]"
            
            # Check message size (should be well under 240 bytes now)
            message_size = len(chunk_message.encode('utf-8'))
            if message_size > 240:
                print(f"[ERROR] Chunk {chunk_num + 1} too large ({message_size} bytes)")
                return False
            
            # Send chunk directly without encryption (data is already encrypted)
            # Use the low-level send function to avoid double encryption
            try:
                self.interface.sendText(chunk_message, destinationId=destination_id, wantAck=True)
            except TypeError:
                try:
                    self.interface.sendText(chunk_message, destinationId=destination_id)
                except Exception as e:
                    print(f"[ERROR] Failed to send chunk {chunk_num + 1}/{total_chunks}: {e}")
                    return False
            except Exception as e:
                print(f"[ERROR] Failed to send chunk {chunk_num + 1}/{total_chunks}: {e}")
                return False
            
            # Small delay between chunks to avoid overwhelming the network
            time.sleep(0.1)
        
        print(f"[OK] Long message sent successfully ({total_chunks} chunks)")
        return True
    
    def send_file(self, node_identifier: str, file_path: str) -> bool:
        """Send a file to a specific node by ID or exact name match
        
        Args:
            node_identifier: Node ID (number) or exact node name (long name or short name)
            file_path: Path to the file to send
            
        Returns:
            True if file transfer started successfully, False otherwise
        """
        # Check if file exists
        if not os.path.exists(file_path):
            print(f"[ERROR] File not found: {file_path}")
            return False
        
        # Check file size (512KB limit)
        file_size = os.path.getsize(file_path)
        max_size = 512 * 1024  # 512KB
        if file_size > max_size:
            print(f"[ERROR] File too large: {file_size} bytes (max {max_size} bytes)")
            return False
        
        # Resolve node identifier to node ID (same logic as send_private_message)
        destination_id = None
        try:
            destination_id = int(node_identifier)
        except ValueError:
            # Try to find exact name match
            nodes = self.get_node_info()
            if not nodes:
                print("[ERROR] No node information available")
                return False
            
            node_identifier_lower = node_identifier.lower()
            matches = []
            
            for node_id, node in nodes.items():
                num = node.get('num', node_id)
                user = node.get('user', {})
                long_name = user.get('longName', '')
                short_name = user.get('shortName', '')
                
                if (long_name and long_name.lower() == node_identifier_lower) or \
                   (short_name and short_name.lower() == node_identifier_lower):
                    matches.append((num, long_name, short_name))
            
            if not matches:
                print(f"[ERROR] No nodes found with exact name: {node_identifier}")
                print("  Use /nodes to see available nodes")
                return False
            
            if len(matches) > 1:
                print(f"[ERROR] Multiple nodes found with name '{node_identifier}':")
                for node_id, long_name, short_name in matches:
                    name_display = long_name if long_name else short_name
                    if not name_display:
                        name_display = f"Node {node_id}"
                    print(f"  Node ID: {node_id} - {name_display} ({short_name if short_name else 'N/A'})")
                print("  Please use the node ID directly to avoid ambiguity")
                return False
            
            destination_id = matches[0][0]
        
        if not destination_id:
            print(f"[ERROR] Could not resolve node: {node_identifier}")
            return False
        
        # Read file
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
        except Exception as e:
            print(f"[ERROR] Failed to read file: {e}")
            return False
        
        filename = os.path.basename(file_path)
        
        # Calculate file hash for verification (use first 16 chars of hash to save space)
        file_hash_full = hashlib.sha256(file_data).hexdigest()
        file_hash = file_hash_full[:16]  # Use first 16 chars for header, verify full hash on reassembly
        
        # Encrypt the entire file first (if encryption is enabled)
        my_node_id = self.get_my_node_id()
        if my_node_id is None:
            print("[ERROR] Cannot get our node ID for encryption")
            return False
        
        key = self.get_encryption_key(str(my_node_id))
        if key is None:
            print("[WARN] No encryption key set for our node, sending file unencrypted")
            encrypted_data = file_data
            is_encrypted = False
        else:
            try:
                from cryptography.fernet import Fernet
                fernet = Fernet(key)
                encrypted_data = fernet.encrypt(file_data)
                is_encrypted = True
            except Exception as e:
                print(f"[ERROR] Failed to encrypt file: {e}")
                return False
        
        # Base64 encode the encrypted data
        encrypted_base64 = base64.b64encode(encrypted_data).decode('utf-8')
        
        # Split encrypted data into chunks (stable chunk size - no encryption overhead per chunk)
        # Meshtastic messages have a limit around 240 bytes
        # We need room for: [FILECHUNK:file_id:chunk_num:total_chunks:data]
        # Metadata is ~30-40 bytes, so we can use ~180 bytes for data
        chunk_size = 180
        total_chunks = (len(encrypted_base64) + chunk_size - 1) // chunk_size
        
        # Generate unique file ID (short)
        file_id = str(uuid.uuid4())[:8]
        
        print(f"[INFO] Sending file '{filename}' ({file_size} bytes, {total_chunks} chunks) to node {destination_id}...")
        
        # Send file header (keep it short)
        # Format: [FILE:file_id:filename:total_chunks:hash16:encrypted]
        # Truncate filename if too long (max 50 chars)
        safe_filename = filename[:50] if len(filename) <= 50 else filename[:47] + "..."
        is_encrypted_flag = "1" if is_encrypted else "0"
        header = f"[FILE:{file_id}:{safe_filename}:{total_chunks}:{file_hash}:{is_encrypted_flag}]"
        if not self._send_encrypted_private_message(header, destination_id):
            print("[ERROR] Failed to send file header")
            return False
        
        # Send chunks (no encryption needed - data is already encrypted)
        for chunk_num in range(total_chunks):
            start = chunk_num * chunk_size
            end = start + chunk_size
            chunk_data = encrypted_base64[start:end]
            
            # Send chunk with metadata (no encryption - data is already encrypted)
            # Format: [FILECHUNK:file_id:chunk_num:total_chunks:data]
            chunk_message = f"[FILECHUNK:{file_id}:{chunk_num}:{total_chunks}:{chunk_data}]"
            
            # Check message size (should be well under 240 bytes now)
            message_size = len(chunk_message.encode('utf-8'))
            if message_size > 240:
                print(f"[ERROR] Chunk {chunk_num + 1} too large ({message_size} bytes)")
                return False
            
            # Send chunk directly without encryption (data is already encrypted)
            # Use the low-level send function to avoid double encryption
            try:
                self.interface.sendText(chunk_message, destinationId=destination_id, wantAck=True)
            except TypeError:
                try:
                    self.interface.sendText(chunk_message, destinationId=destination_id)
                except Exception as e:
                    print(f"[ERROR] Failed to send chunk {chunk_num + 1}/{total_chunks}: {e}")
                    return False
            except Exception as e:
                print(f"[ERROR] Failed to send chunk {chunk_num + 1}/{total_chunks}: {e}")
                return False
            
            # Small delay between chunks to avoid overwhelming the network
            time.sleep(0.1)
        
        print(f"[OK] File '{filename}' sent successfully ({total_chunks} chunks)")
        return True
    
    def _handle_file_chunk(self, text: str, from_id: str, from_name: str) -> bool:
        """Handle incoming file chunk or header
        
        Returns:
            True if this was a file message (handled), False otherwise
        """
        # Check for file header
        if text.startswith("[FILE:"):
            try:
                # Parse: [FILE:file_id:filename:total_chunks:hash:encrypted]
                # Filename might contain colons, so parse from the end
                if not text.endswith(']'):
                    # Header doesn't end with ], might be malformed
                    print(f"[DEBUG] File header doesn't end with ]: {text!r}")
                    return False
                content = text[6:-1]  # Remove [FILE: and ]
                # Find the last 3 colons (for total_chunks, file_hash, and end)
                last_colon_idx = content.rfind(':')
                if last_colon_idx == -1:
                    return False
                file_hash = content[last_colon_idx+1:]
                content = content[:last_colon_idx]
                
                second_last_colon_idx = content.rfind(':')
                if second_last_colon_idx == -1:
                    return False
                # Check if there's an encryption flag (new format) or just total_chunks (old format)
                encryption_flag = None
                try:
                    # Try to parse as encryption flag first
                    potential_flag = content[second_last_colon_idx+1:]
                    if potential_flag in ['0', '1']:
                        # This is the encryption flag, get total_chunks from previous colon
                        encryption_flag = potential_flag
                        content = content[:second_last_colon_idx]
                        second_last_colon_idx = content.rfind(':')
                        if second_last_colon_idx == -1:
                            return False
                        total_chunks = int(content[second_last_colon_idx+1:])
                    else:
                        # Old format, no encryption flag
                        total_chunks = int(potential_flag)
                except ValueError:
                    return False
                content = content[:second_last_colon_idx]
                
                first_colon_idx = content.find(':')
                if first_colon_idx == -1:
                    return False
                file_id = content[:first_colon_idx]
                filename = content[first_colon_idx+1:]
                
                if file_id and filename and total_chunks > 0 and file_hash:
                    # Parse encryption flag (optional, for backwards compatibility)
                    is_encrypted = encryption_flag == "1" if encryption_flag is not None else False
                    
                    # Initialize file transfer
                    # Store partial hash (16 chars) for now, will verify with full hash on reassembly
                    self.file_transfers[file_id] = {
                        'filename': filename,
                        'total_chunks': total_chunks,
                        'received_chunks': {},
                        'from_id': from_id,
                        'from_name': from_name,
                        'file_hash_partial': file_hash,  # Store partial hash from header
                        'is_encrypted': is_encrypted,  # Whether the file data is encrypted
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    # Check if we have orphaned chunks for this file_id
                    if file_id in self.orphaned_chunks:
                        orphaned = self.orphaned_chunks[file_id]
                        print(f"\n[FILE] Receiving file '{filename}' from {from_name} ({from_id}) - {total_chunks} chunks")
                        if orphaned:
                            print(f"[INFO] Found {len(orphaned)} orphaned chunks, applying them...")
                            for orphan in orphaned:
                                if orphan['chunk_num'] < total_chunks:
                                    self.file_transfers[file_id]['received_chunks'][orphan['chunk_num']] = orphan['chunk_data']
                            # Check if we now have all chunks
                            if len(self.file_transfers[file_id]['received_chunks']) == total_chunks:
                                self._reassemble_file(file_id)
                        del self.orphaned_chunks[file_id]
                    else:
                        print(f"\n[FILE] Receiving file '{filename}' from {from_name} ({from_id}) - {total_chunks} chunks")
                    return True
                else:
                    # Parsing succeeded but required fields are missing - this shouldn't happen
                    print(f"[DEBUG] File header parsing incomplete: file_id={file_id!r}, filename={filename!r}, total_chunks={total_chunks}, file_hash={file_hash!r}")
                    return False
            except Exception as e:
                print(f"[ERROR] Failed to parse file header: {e}")
                import traceback
                traceback.print_exc()
                return False
        
        # Check for file chunk
        elif text.startswith("[FILECHUNK:"):
            try:
                # Parse: [FILECHUNK:file_id:chunk_num:total_chunks:data]
                parts = text[11:-1].split(':')  # Remove [FILECHUNK: and ]
                if len(parts) >= 4:
                    file_id = parts[0]
                    chunk_num = int(parts[1])
                    total_chunks = int(parts[2])
                    chunk_data = ':'.join(parts[3:])  # Rejoin in case data contains ':'
                    
                    # Check if we have this file transfer
                    if file_id not in self.file_transfers:
                        # Store as orphaned chunk - header might arrive later
                        if file_id not in self.orphaned_chunks:
                            self.orphaned_chunks[file_id] = []
                        self.orphaned_chunks[file_id].append({
                            'chunk_num': chunk_num,
                            'total_chunks': total_chunks,
                            'chunk_data': chunk_data,
                            'from_id': from_id,
                            'from_name': from_name,
                            'timestamp': datetime.now().isoformat()
                        })
                        # Only warn if we have many orphaned chunks (header might be coming)
                        # But also check if we have all chunks - header probably lost
                        if len(self.orphaned_chunks[file_id]) >= total_chunks:
                            # We have all chunks but no header - header probably lost
                            print(f"[WARN] Received {len(self.orphaned_chunks[file_id])}/{total_chunks} chunks for unknown file {file_id}, header may be missing")
                        return True  # Still handled
                    
                    transfer = self.file_transfers[file_id]
                    
                    # Store chunk
                    transfer['received_chunks'][chunk_num] = chunk_data
                    
                    # Check if all chunks received
                    if len(transfer['received_chunks']) == transfer['total_chunks']:
                        # Reassemble file
                        self._reassemble_file(file_id)
                    
                    return True
            except Exception as e:
                print(f"[ERROR] Failed to parse file chunk: {e}")
                return False
        
        return False
    
    def _handle_message_chunk(self, text: str, from_id: str, from_name: str) -> bool:
        """Handle incoming long message chunk or header
        
        Returns:
            True if this was a message chunk (handled), False otherwise
        """
        # Check for message header
        if text.startswith("[MSG:"):
            try:
                # Parse: [MSG:message_id:total_chunks:encrypted]
                if text.endswith(']'):
                    content = text[5:-1]  # Remove [MSG: and ]
                    parts = content.split(':')
                    if len(parts) >= 3:
                        message_id = parts[0]
                        total_chunks = int(parts[1])
                        is_encrypted = parts[2] == "1"
                        
                        # Initialize message transfer
                        self.message_transfers[message_id] = {
                            'total_chunks': total_chunks,
                            'received_chunks': {},
                            'from_id': from_id,
                            'from_name': from_name,
                            'is_encrypted': is_encrypted,
                            'timestamp': datetime.now().isoformat()
                        }
                        
                        # Check if we have orphaned chunks for this message_id
                        if message_id in self.orphaned_chunks:
                            orphaned = self.orphaned_chunks[message_id]
                            print(f"\n[MSG] Receiving long message from {from_name} ({from_id}) - {total_chunks} chunks")
                            if orphaned:
                                print(f"[INFO] Found {len(orphaned)} orphaned chunks, applying them...")
                                for orphan in orphaned:
                                    if orphan['chunk_num'] < total_chunks:
                                        self.message_transfers[message_id]['received_chunks'][orphan['chunk_num']] = orphan['chunk_data']
                                # Check if we now have all chunks
                                if len(self.message_transfers[message_id]['received_chunks']) == total_chunks:
                                    self._reassemble_message(message_id)
                            del self.orphaned_chunks[message_id]
                        else:
                            print(f"\n[MSG] Receiving long message from {from_name} ({from_id}) - {total_chunks} chunks")
                        return True
            except Exception as e:
                print(f"[ERROR] Failed to parse message header: {e}")
                return False
        
        # Check for message chunk
        elif text.startswith("[MSGCHUNK:"):
            try:
                # Parse: [MSGCHUNK:message_id:chunk_num:total_chunks:data]
                parts = text[10:-1].split(':')  # Remove [MSGCHUNK: and ]
                if len(parts) >= 4:
                    message_id = parts[0]
                    chunk_num = int(parts[1])
                    total_chunks = int(parts[2])
                    chunk_data = ':'.join(parts[3:])  # Rejoin in case data contains ':'
                    
                    # Check if we have this message transfer
                    if message_id not in self.message_transfers:
                        # Store as orphaned chunk - header might arrive later
                        if message_id not in self.orphaned_chunks:
                            self.orphaned_chunks[message_id] = []
                        self.orphaned_chunks[message_id].append({
                            'chunk_num': chunk_num,
                            'total_chunks': total_chunks,
                            'chunk_data': chunk_data,
                            'from_id': from_id,
                            'from_name': from_name,
                            'timestamp': datetime.now().isoformat()
                        })
                        # Only warn if we have many orphaned chunks (header might be coming)
                        if len(self.orphaned_chunks[message_id]) > 10:
                            # Too many orphaned chunks - header probably lost
                            print(f"[WARN] Received {len(self.orphaned_chunks[message_id])} chunks for unknown message {message_id}, header may be missing")
                        return True  # Still handled
                    
                    transfer = self.message_transfers[message_id]
                    
                    # Store chunk
                    transfer['received_chunks'][chunk_num] = chunk_data
                    
                    # Check if all chunks received
                    if len(transfer['received_chunks']) == transfer['total_chunks']:
                        # Reassemble message
                        self._reassemble_message(message_id)
                    
                    return True
            except Exception as e:
                print(f"[ERROR] Failed to parse message chunk: {e}")
                return False
        
        return False
    
    def _reassemble_message(self, message_id: str):
        """Reassemble a long message from received chunks"""
        if message_id not in self.message_transfers:
            return
        
        transfer = self.message_transfers[message_id]
        total_chunks = transfer['total_chunks']
        received_chunks = transfer['received_chunks']
        is_encrypted = transfer.get('is_encrypted', False)
        from_id = transfer['from_id']
        from_name = transfer['from_name']
        
        # Check if we have all chunks
        if len(received_chunks) != total_chunks:
            print(f"[ERROR] Missing chunks for message: {len(received_chunks)}/{total_chunks}")
            return
        
        # Reassemble base64 string (this is the encrypted data)
        chunks = []
        for i in range(total_chunks):
            if i not in received_chunks:
                print(f"[ERROR] Missing chunk {i} for message")
                del self.message_transfers[message_id]
                return
            chunks.append(received_chunks[i])
        
        encrypted_base64 = ''.join(chunks)
        
        # Decode from base64 to get encrypted data
        try:
            encrypted_data = base64.b64decode(encrypted_base64)
        except Exception as e:
            print(f"[ERROR] Failed to decode encrypted message data: {e}")
            del self.message_transfers[message_id]
            return
        
        # Decrypt if needed
        if is_encrypted:
            # Get sender's key for decryption
            key = self.get_encryption_key(str(from_id))
            if key is None:
                print(f"[ERROR] No encryption key available for node {from_id} to decrypt message")
                del self.message_transfers[message_id]
                return
            
            try:
                from cryptography.fernet import Fernet
                fernet = Fernet(key)
                message_data = fernet.decrypt(encrypted_data)
                message_text = message_data.decode('utf-8')
            except Exception as e:
                print(f"[ERROR] Failed to decrypt message data: {e}")
                del self.message_transfers[message_id]
                return
        else:
            message_text = encrypted_data.decode('utf-8')
        
        # Display the reassembled message
        timestamp = datetime.now().isoformat()
        enc_indicator = " [ENCRYPTED]" if is_encrypted else ""
        print(f"\n[{timestamp}] {from_name} ({from_id}){enc_indicator}: {message_text}")
        
        # Add to history
        message = {
            'timestamp': timestamp,
            'from_id': str(from_id),
            'from_name': from_name,
            'text': message_text,
            'encrypted': is_encrypted
        }
        self.add_to_history(message)
        
        print("> ", end='', flush=True)
        
        # Clean up
        del self.message_transfers[message_id]
    
    def _reassemble_file(self, file_id: str):
        """Reassemble a file from received chunks"""
        if file_id not in self.file_transfers:
            return
        
        transfer = self.file_transfers[file_id]
        filename = transfer['filename']
        total_chunks = transfer['total_chunks']
        received_chunks = transfer['received_chunks']
        file_hash_partial = transfer.get('file_hash_partial', '')
        from_name = transfer['from_name']
        
        # Check if we have all chunks
        if len(received_chunks) != total_chunks:
            print(f"[ERROR] Missing chunks for file '{filename}': {len(received_chunks)}/{total_chunks}")
            return
        
        # Reassemble base64 string
        chunks = []
        for i in range(total_chunks):
            if i not in received_chunks:
                print(f"[ERROR] Missing chunk {i} for file '{filename}'")
                del self.file_transfers[file_id]
                return
            chunks.append(received_chunks[i])
        
        file_base64 = ''.join(chunks)
        
        # Decode from base64
        try:
            file_data = base64.b64decode(file_base64)
        except Exception as e:
            print(f"[ERROR] Failed to decode file data: {e}")
            del self.file_transfers[file_id]
            return
        
        # Verify hash (compare first 16 chars of full hash with partial hash from header)
        calculated_hash_full = hashlib.sha256(file_data).hexdigest()
        calculated_hash_partial = calculated_hash_full[:16]
        if file_hash_partial and calculated_hash_partial != file_hash_partial:
            print(f"[ERROR] File hash mismatch for '{filename}' - file may be corrupted")
            print(f"  Expected: {file_hash_partial}, Got: {calculated_hash_partial}")
            del self.file_transfers[file_id]
            return
        
        # Save file
        # Create downloads directory if it doesn't exist
        downloads_dir = "downloads"
        if not os.path.exists(downloads_dir):
            os.makedirs(downloads_dir)
        
        # Add timestamp to filename to avoid overwrites
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name, ext = os.path.splitext(filename)
        safe_filename = f"{base_name}_{timestamp}{ext}"
        file_path = os.path.join(downloads_dir, safe_filename)
        
        try:
            with open(file_path, 'wb') as f:
                f.write(file_data)
            
            file_size = len(file_data)
            print(f"\n[FILE] File '{filename}' received from {from_name} ({file_size} bytes)")
            print(f"       Saved to: {file_path}")
            
            # Clean up
            del self.file_transfers[file_id]
        except Exception as e:
            print(f"[ERROR] Failed to save file: {e}")
            del self.file_transfers[file_id]
    
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
    
    def format_timestamp(self, timestamp: int) -> str:
        """Convert Unix timestamp to human readable format"""
        try:
            dt = datetime.fromtimestamp(timestamp)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, OSError, TypeError):
            return str(timestamp)
    
    def format_position(self, position: Dict) -> str:
        """Format position and generate Google Maps URL"""
        if not position:
            return "N/A"
        
        lat = position.get('latitude')
        lon = position.get('longitude')
        
        if lat is not None and lon is not None:
            # Generate Google Maps URL
            url = f"https://www.google.com/maps?q={lat},{lon}"
            return f"{lat}, {lon} ({url})"
        
        # Fallback to integer coordinates if available
        lat_i = position.get('latitudeI')
        lon_i = position.get('longitudeI')
        if lat_i is not None and lon_i is not None:
            # Convert from integer format (divide by 1e7)
            lat = lat_i / 1e7
            lon = lon_i / 1e7
            url = f"https://www.google.com/maps?q={lat},{lon}"
            return f"{lat}, {lon} ({url})"
        
        return "N/A"
    
    def resolve_node_name(self, pattern: str) -> List[tuple]:
        """Resolve node names (with wildcards) to node IDs
        
        Args:
            pattern: Name pattern with wildcards (e.g., '*my_node*', 'test*', '*device')
        
        Returns:
            List of tuples (node_id, long_name, short_name) for matching nodes
        """
        nodes = self.get_node_info()
        if not nodes:
            return []
        
        matches = []
        for node_id, node in nodes.items():
            num = node.get('num', node_id)
            user = node.get('user', {})
            long_name = user.get('longName', '')
            short_name = user.get('shortName', '')
            
            # Match against both long name and short name (case-insensitive)
            pattern_lower = pattern.lower()
            long_name_lower = long_name.lower() if long_name else ''
            short_name_lower = short_name.lower() if short_name else ''
            
            if (fnmatch.fnmatch(long_name_lower, pattern_lower) or 
                fnmatch.fnmatch(short_name_lower, pattern_lower) or
                fnmatch.fnmatch(str(num), pattern)):
                matches.append((num, long_name, short_name))
        
        return matches
    
    def show_resolve(self, pattern: str):
        """Display node IDs that match the given name pattern"""
        if not pattern:
            print("Usage: /resolve <pattern>")
            print("Example: /resolve *my_node*")
            print("Example: /resolve test*")
            print("Example: /resolve *device")
            return
        
        matches = self.resolve_node_name(pattern)
        if not matches:
            print(f"No nodes found matching pattern: {pattern}")
            return
        
        # Get current device node ID
        my_node_id = self.get_my_node_id()
        
        print(f"\n=== Nodes matching '{pattern}' ===")
        for node_id, long_name, short_name in matches:
            name_display = long_name if long_name else short_name
            if not name_display:
                name_display = f"Node {node_id}"
            
            # Check if this is the current device
            is_current = (my_node_id is not None and str(node_id) == str(my_node_id))
            current_marker = " [CURRENT DEVICE]" if is_current else ""
            
            print(f"  Node ID: {node_id} - {name_display} ({short_name if short_name else 'N/A'}){current_marker}")
        print()
    
    def get_hop_count(self, node: Dict) -> Optional[int]:
        """Extract hop count from node data
        
        Returns:
            Hop count if available, None otherwise
        """
        # Try various possible fields for hop information
        # hopLimit is the maximum hops, but we want actual hops away
        if 'hopLimit' in node:
            # hopLimit might be the actual hops away in some versions
            hop_limit = node.get('hopLimit')
            if hop_limit is not None:
                return hop_limit
        
        # Check for hopsAway field
        if 'hopsAway' in node:
            hops_away = node.get('hopsAway')
            if hops_away is not None:
                return hops_away
        
        # Check in position data
        position = node.get('position', {})
        if isinstance(position, dict):
            if 'hopsAway' in position:
                return position.get('hopsAway')
        
        # Check for hopStart (sometimes used to indicate distance)
        if 'hopStart' in node:
            hop_start = node.get('hopStart')
            if hop_start is not None:
                return hop_start
        
        # Check in route information
        route = node.get('route', {})
        if isinstance(route, dict):
            if 'hops' in route:
                return route.get('hops')
        
        return None
    
    def get_my_node_id(self) -> Optional[int]:
        """Get the current device's node ID"""
        if not self.interface:
            return None
        try:
            node_info = self.interface.getMyNodeInfo()
            return node_info.get('num')
        except Exception:
            return None
    
    def get_port_info(self) -> Dict[str, str]:
        """Get full port information including name and description
        
        Returns:
            Dictionary with 'port', 'description', 'manufacturer', and 'full_name'
        """
        port_info = {
            'port': 'Unknown',
            'description': '',
            'manufacturer': '',
            'full_name': 'Unknown'
        }
        
        if not self.interface:
            return port_info
        
        # Get the port name
        port_name = None
        if hasattr(self.interface, 'port') and self.interface.port:
            port_name = self.interface.port
        elif hasattr(self.interface, 'stream') and hasattr(self.interface.stream, 'port'):
            port_name = self.interface.stream.port
        elif hasattr(self.interface, 'devPath'):
            port_name = self.interface.devPath
        
        if port_name:
            port_info['port'] = port_name
            
            # Try to get full port information from serial port listing
            if list_ports:
                try:
                    ports = list_ports.comports()
                    for port in ports:
                        if port.device == port_name:
                            port_info['description'] = port.description or ''
                            port_info['manufacturer'] = port.manufacturer or ''
                            
                            # Build full name
                            parts = [port_name]
                            if port.description:
                                parts.append(port.description)
                            if port.manufacturer:
                                parts.append(f"({port.manufacturer})")
                            
                            port_info['full_name'] = ' - '.join(parts)
                            break
                except Exception:
                    # If we can't get detailed info, just use the port name
                    port_info['full_name'] = port_name
            else:
                port_info['full_name'] = port_name
        
        return port_info
    
    def show_nodes(self, pattern: Optional[str] = None):
        """Display connected nodes with all available information
        
        Args:
            pattern: Optional wildcard pattern to filter nodes (e.g., '*my_node*')
        """
        nodes = self.get_node_info()
        if not nodes:
            print("No node information available")
            return
        
        # Get current device node ID
        my_node_id = self.get_my_node_id()
        
        # Filter nodes by pattern if provided
        filtered_nodes = {}
        if pattern:
            pattern_lower = pattern.lower()
            for node_id, node in nodes.items():
                num = node.get('num', node_id)
                user = node.get('user', {})
                long_name = user.get('longName', '')
                short_name = user.get('shortName', '')
                
                long_name_lower = long_name.lower() if long_name else ''
                short_name_lower = short_name.lower() if short_name else ''
                
                if (fnmatch.fnmatch(long_name_lower, pattern_lower) or 
                    fnmatch.fnmatch(short_name_lower, pattern_lower) or
                    fnmatch.fnmatch(str(num), pattern)):
                    filtered_nodes[node_id] = node
            nodes = filtered_nodes
        
        if not nodes:
            if pattern:
                print(f"\nNo nodes found matching pattern: {pattern}")
            else:
                print("No node information available")
            return
        
        title = "=== Connected Nodes"
        if pattern:
            title += f" (filtered: '{pattern}')"
        title += " ==="
        print(f"\n{title}")
        print("  (Use /pm <node_id> <message> to send private message)")
        print()
        
        # Sort nodes: first by hops away (ascending), then by lastHeard (descending - most recent first)
        def sort_key(item):
            node_id, node = item
            # Get hops away (use a large number if not available, so they sort last)
            hop_count = self.get_hop_count(node)
            hops = hop_count if hop_count is not None else 999
            
            # Get lastHeard (use 0 if not available, so they sort last)
            last_heard = node.get('lastHeard', 0)
            
            # Return tuple: (hops, -lastHeard) 
            # Negative lastHeard because we want descending order (most recent first)
            return (hops, -last_heard)
        
        # Sort the nodes
        sorted_nodes = sorted(nodes.items(), key=sort_key)
        
        for node_id, node in sorted_nodes:
            num = node.get('num', node_id)
            user = node.get('user', {})
            long_name = user.get('longName', 'Unknown')
            short_name = user.get('shortName', 'Unknown')
            
            # Check if this is the current device
            is_current = (my_node_id is not None and str(num) == str(my_node_id))
            current_marker = " [CURRENT DEVICE]" if is_current else ""
            
            # Get hop count
            hop_count = self.get_hop_count(node)
            hop_info = ""
            if hop_count is not None:
                hop_info = f" [{hop_count} hop{'s' if hop_count != 1 else ''} away]"
            
            print(f"--- Node ID: {num} ({long_name} / {short_name}){current_marker}{hop_info} ---")
            print()
            
            # Display specific fields in simplified format
            user = node.get('user', {})
            position = node.get('position', {})
            
            # id
            if 'id' in user:
                print(f"id: {user['id']}")
            
            # longName
            if long_name and long_name != 'Unknown':
                print(f"longName: {long_name}")
            
            # shortName
            if short_name and short_name != 'Unknown':
                print(f"shortName: {short_name}")
            
            # hopsAway
            hop_count = self.get_hop_count(node)
            if hop_count is not None:
                print(f"hopsAway: {hop_count}")
            
            # macaddr
            if 'macaddr' in user:
                print(f"macaddr: {user['macaddr']}")
            
            # hwModel
            if 'hwModel' in node:
                print(f"hwModel: {node['hwModel']}")
            
            # snr
            if 'snr' in node:
                print(f"snr: {node['snr']}")
            
            # lastHeard (convert to human readable)
            if 'lastHeard' in node:
                last_heard = node['lastHeard']
                readable_time = self.format_timestamp(last_heard)
                print(f"lastHeard: {readable_time}")
            
            # uptimeSeconds
            device_metrics = node.get('deviceMetrics', {})
            if 'uptimeSeconds' in device_metrics:
                print(f"uptimeSeconds: {device_metrics['uptimeSeconds']}")
            
            # position (with Google Maps URL)
            if position:
                pos_str = self.format_position(position)
                print(f"position: {pos_str}")
            
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
            
            # Get and display full port information
            port_info = self.get_port_info()
            print(f"Serial Port: {port_info['full_name']}")
            if port_info['description']:
                print(f"  Description: {port_info['description']}")
            if port_info['manufacturer']:
                print(f"  Manufacturer: {port_info['manufacturer']}")
            
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
        print("  /nodes    - List connected nodes: /nodes [pattern] (supports wildcards)")
        print("  /pm       - Send private message: /pm <node_id_or_name> <message>")
        print("  /resolve  - Resolve name to node ID: /resolve <pattern> (supports wildcards)")
        print("  /setname  - Set node name: /setname <long_name> <short_name>")
        print("  /reboot   - Reboot the device: /reboot [delay_seconds]")
        print("  /history  - Show message history")
        print("  /broadcast - Send broadcast message: /broadcast <message>")
        print("  /setkey   - Set encryption key for node: /setkey <node_id_or_name> <password>")
        print("  /file     - Send file: /file <node_id_or_name> <path_to_file>")
        print("  /clear    - Clear screen")
        print("  /quit     - Exit client")
        print("\nUse commands to send messages. Type /help for available commands.")
        print("Use /pm <node_id_or_name> <message> to send a private message (exact name match).")
        print("Use /broadcast <message> to send a broadcast message to all nodes.")
        print("Use /resolve <pattern> to find node IDs by name (e.g., /resolve *my_node*).")
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
                            print("  /nodes    - List connected nodes: /nodes [pattern] (supports wildcards)")
                            print("  /pm       - Send private message: /pm <node_id_or_name> <message>")
                            print("  /resolve  - Resolve name to node ID: /resolve <pattern> (supports wildcards)")
                            print("  /setname  - Set node name: /setname <long_name> <short_name>")
                            print("  /reboot   - Reboot the device: /reboot [delay_seconds]")
                            print("  /history  - Show message history")
                            print("  /broadcast - Send broadcast message: /broadcast <message>")
                            print("  /setkey   - Set encryption key for node: /setkey <node_id_or_name> <password>")
                            print("  /file     - Send file: /file <node_id_or_name> <path_to_file>")
                            print("  /clear    - Clear screen")
                            print("  /quit     - Exit client")
                            print()
                        elif cmd == '/status':
                            self.show_status()
                        elif cmd.startswith('/nodes'):
                            # Parse nodes command: /nodes [pattern]
                            parts = user_input.split(' ', 1)
                            pattern = parts[1] if len(parts) > 1 else None
                            self.show_nodes(pattern=pattern)
                        elif cmd.startswith('/pm ') or cmd.startswith('/private '):
                            # Parse private message command: /pm <node_id_or_name> <message>
                            parts = user_input.split(' ', 2)
                            if len(parts) < 3:
                                print("Usage: /pm <node_id_or_name> <message>")
                                print("Example: /pm 1234567890 Hello there!")
                                print("Example: /pm joker13 Hello there!  (exact name match)")
                                print("Use /nodes to see available nodes")
                                print("Use /resolve <pattern> to find nodes by name pattern")
                            else:
                                node_identifier = parts[1]
                                message = parts[2]
                                self.send_private_message(node_identifier, message)
                        elif cmd.startswith('/resolve'):
                            # Parse resolve command: /resolve [pattern]
                            parts = user_input.split(' ', 1)
                            if len(parts) < 2:
                                # No pattern provided, default to * (match all)
                                pattern = '*'
                            else:
                                pattern = parts[1]
                            self.show_resolve(pattern)
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
                        elif cmd.startswith('/broadcast ') or cmd.startswith('/bc '):
                            # Parse broadcast command: /broadcast <message>
                            parts = user_input.split(' ', 1)
                            if len(parts) < 2:
                                print("Usage: /broadcast <message>")
                                print("Example: /broadcast Hello everyone!")
                                print("Sends a message to all nodes in the mesh network.")
                            else:
                                message = parts[1]
                                self.send_message(message, skip_confirmation=True)
                        elif cmd.startswith('/setkey '):
                            # Parse setkey command: /setkey <node_id_or_name> <password>
                            parts = user_input.split(' ', 2)
                            if len(parts) < 3:
                                print("Usage: /setkey <node_id_or_name> <password>")
                                print("Example: /setkey 1234567890 mySecretPassword")
                                print("Example: /setkey joker13 mySecretPassword")
                                print("Sets an encryption key for private messages with this node.")
                                print("Both parties must use the same password for encryption to work.")
                            else:
                                node_identifier = parts[1]
                                password = parts[2]
                                
                                # Resolve node identifier to node ID
                                node_id = None
                                try:
                                    node_id = int(node_identifier)
                                except ValueError:
                                    # Try to resolve by name
                                    nodes = self.get_node_info()
                                    node_identifier_lower = node_identifier.lower()
                                    for nid, node in nodes.items():
                                        num = node.get('num', nid)
                                        user = node.get('user', {})
                                        long_name = user.get('longName', '')
                                        short_name = user.get('shortName', '')
                                        if (long_name and long_name.lower() == node_identifier_lower) or \
                                           (short_name and short_name.lower() == node_identifier_lower):
                                            node_id = num
                                            break
                                
                                if node_id is None:
                                    print(f"[ERROR] Node not found: {node_identifier}")
                                    print("  Use /nodes to see available nodes")
                                else:
                                    if self.set_encryption_key(str(node_id), password):
                                        print(f"[OK] Encryption key set for node {node_id}")
                                        print("  Private messages with this node will now be encrypted")
                                        print("  Make sure the other party uses the same password!")
                        elif cmd.startswith('/file '):
                            # Parse file command: /file <node_id_or_name> <path_to_file>
                            parts = user_input.split(' ', 2)
                            if len(parts) < 3:
                                print("Usage: /file <node_id_or_name> <path_to_file>")
                                print("Example: /file 1234567890 /path/to/file.txt")
                                print("Example: /file joker13 document.pdf")
                                print("Sends a file (up to 512KB) to the specified node.")
                                print("The file will be encrypted if encryption is enabled for that node.")
                            else:
                                node_identifier = parts[1]
                                file_path = parts[2]
                                self.send_file(node_identifier, file_path)
                        elif cmd == '/clear':
                            os.system('cls' if os.name == 'nt' else 'clear')
                        else:
                            print(f"Unknown command: {user_input}. Type /help for help.")
                    else:
                        # Don't send messages by default - require explicit command
                        print(f"Unknown command or message. Type /help for available commands.")
                        print("Use /broadcast <message> to send a broadcast message.")
                        print("Use /pm <node_id_or_name> <message> to send a private message (exact name match).")
                
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
  %(prog)s --list-ports       # List available serial ports
        """
    )
    
    parser.add_argument('-p', '--port', help='Serial port (e.g., COM3 or /dev/ttyUSB0)')
    parser.add_argument('--list-ports', action='store_true', help='List available serial ports and exit')
    parser.add_argument('--history-file', default='meshastic_history.json', 
                       help='File to store message history (default: meshastic_history.json)')
    
    args = parser.parse_args()
    
    client = MeshasticClient(port=args.port, history_file=args.history_file)
    
    # Handle list ports command (doesn't need connection)
    if args.list_ports:
        client.list_serial_ports()
        sys.exit(0)
    
    # Interactive mode
    client.interactive_mode()


if __name__ == '__main__':
    main()

