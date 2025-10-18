#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import threading
from script_base.log import logger

# check frida is installed
try:
    import frida
except ImportError:
    logger.error("Frida Python bindings are not installed. Please install them via 'pip install frida'.")

# check packaging is installed
try:
    from packaging.version import parse as parse_version
except ImportError:
    logger.error("The 'packaging' library is not installed. Please install it via 'pip install packaging'.")

class FridaScriptExecutor:
    """
    A base class for executing Frida scripts and communicating with them.
    Encapsulates the common logic for device discovery, process attachment, script loading, RPC calls, and message handling.
    """
    def __init__(self, frida_script_path: str, device_id: str = None):
        """
        Initializes the FridaScriptExecutor.

        :param frida_script_path: The path to the Frida .js script to load.
        :param device_id: (Optional) The ID of the specific device to connect to. If None, connects to the default USB device.
        """
        if not os.path.exists(frida_script_path):
            raise FileNotFoundError(f"Frida script not found at: {frida_script_path}")
            
        self.device_id = device_id
        self.frida_script_path = frida_script_path
        
        self.device = None
        self.session = None
        self.script = None
        self.script_content = None
        
        self.message_event = threading.Event()
        self.result_data = None
        self.error_occurred = False

    def _initialize_device(self):
        """Gets and initializes the Frida device."""
        logger.debug("Initializing Frida device...")
        try:
            if self.device_id:
                self.device = frida.get_device(self.device_id)
            else:
                self.device = frida.get_usb_device(timeout=5)
            logger.debug(f"Found device: {self.device.name}")
        except frida.ServerNotRunningError:
            logger.error("Error: Frida server is not running on the device. Please start it first.", exc_info=True)
            raise
        except frida.TransportError as e:
            logger.error(f"Error connecting to device: {e}. Is it connected?", exc_info=True)
            raise
        except Exception as e:
            logger.error(f"An unexpected error occurred while getting the device: {e}", exc_info=True)
            raise

    def on_message(self, message, data):
        """
        Callback handler for messages from the Frida script.
        """
        if message['type'] == 'send':
            payload = message.get('payload', {})
            # Check for a specific return result
            if isinstance(payload, dict) and 'type' in payload:
                if payload['type'] == 'result':
                    self.result_data = payload.get('data')
                    self.message_event.set()
                elif payload['type'] == 'finish':
                    self.message_event.set()
                elif payload['type'] == 'debug':
                    logger.debug(f"[Frida]: {payload.get('message', 'No message')}")
                elif payload['type'] == 'info':
                    logger.info(f"[Frida]: {payload.get('message', 'No message')}")
                elif payload['type'] == 'warning':
                    logger.warning(f"[Frida]: {payload.get('message', 'No message')}") 
                elif payload['type'] == 'error':
                    logger.error(f"[Frida]: {payload.get('message', 'Unknown error')}")
                    self.error_occurred = True
                    self.message_event.set()
        elif message['type'] == 'error':
            logger.error(f"Frida script error: {message.get('description', 'No description')}")
            self.error_occurred = True
            self.message_event.set()

    def _load_script_legacy(self):
        """Loads script by directly reading the file (for Frida < 17)."""
        logger.debug("Loading and injecting Frida script (legacy mode)...")
        try:
            with open(self.frida_script_path, 'r', encoding='utf-8') as f:
                self.script_content = f.read()
            self.script = self.session.create_script(self.script_content)
            self.script.on('message', self.on_message)
            self.script.load()
            logger.debug("Script injected successfully.")
        except Exception as e:
            logger.error(f"Failed to load or inject script: {e}", exc_info=True)
            raise

    def _load_script_with_compiler(self):
        """Loads script using the compiler (for Frida 17+)."""
        logger.debug("Compiling and injecting Frida script (Frida 17+ mode)...")
        try:
            compiler = frida.Compiler()
            
            def on_diagnostics(diag):
                logger.warning(f"[Frida Compiler]: {diag}")
            compiler.on("diagnostics", on_diagnostics)
            
            project_root = os.path.dirname(self.frida_script_path)
            self.script_content = compiler.build(self.frida_script_path, project_root=project_root)
            
            self.script = self.session.create_script(self.script_content)
            self.script.on('message', self.on_message)
            self.script.load()
            logger.debug("Script injected successfully.")
        except Exception as e:
            error_str = str(e).lower()
            # Check for the specific compilation failure related to module resolution
            if "compilation failed" in error_str:
                project_root = os.path.dirname(self.frida_script_path)
                bridge_path = os.path.join(project_root, 'node_modules', 'frida-java-bridge')
                
                # Check if the script actually imports the bridge and if it's missing
                try:
                    with open(self.frida_script_path, 'r', encoding='utf-8') as f:
                        script_code = f.read()
                    if 'from "frida-java-bridge"' in script_code and not os.path.exists(bridge_path):
                        logger.error(
                            "Script compilation failed. This is likely because 'frida-java-bridge' is not installed.\n"
                            f"Please run the following commands in the script's directory ('{project_root}'):\n"
                            "1. npm init -y (if no package.json exists)\n"
                            "2. npm install frida-java-bridge"
                        )
                        return
                        # We've provided a specific error, so we can just raise the original exception without the full traceback
                except Exception:
                    # Fallback to the generic error if file reading fails or for other reasons
                    pass

    def _load_script(self):
        """
        Loads and injects the Frida script, automatically handling different Frida versions.
        """
        # The version check requires the 'packaging' library.
        # pip install packaging
        if parse_version(frida.__version__) >= parse_version("17.0.0"):
            self._load_script_with_compiler()
        else:
            self._load_script_legacy()
        
    def _get_frida_tool_version(self):
        """Gets the version of the Frida tool installed on the host machine."""
        try:
            from script_base.utils import run_command
            
            result = run_command("frida --version", check_output=True, shell=True)
            if result:
                return result
            else:
                logger.warning("Could not determine Frida tool version.")
                return None
        except Exception as e:
            logger.error(f"Error getting Frida tool version: {e}", exc_info=True)
            return None
        
    def _get_frida_server_version(self):
        """Gets the version of the Frida server running on the device."""
        try:
            if not self.device:
                self._initialize_device()
            from android_util_impls.manager import android_util_manager
            from script_base.utils import run_command
            android_util = android_util_manager.select()
            adb_cmd = android_util.get_adb_command(self.device)
            if not adb_cmd:
                return False
            command = f"{adb_cmd} shell data/local/tmp/frida --version"
            result = run_command(command, check_output=True, shell=True)
            version = result.strip()
            logger.info(f"Frida server version on device: {version}")
            return version
        except Exception as e:
            logger.error(f"Error getting Frida server version: {e}", exc_info=True)
            return None
        

    def attach(self, target):
        """
        Attaches to the target process.

        :param target: The PID (int) or name (str) of the process.
        """
        if not self.device:
            self._initialize_device()
        
        logger.debug(f"Attaching to target: '{target}'...")
        try:
            self.session = self.device.attach(target)
            logger.debug(f"Attached to process with PID: {target}")
            self._load_script()
        # check frida server is running
        except frida.ServerNotRunningError:
            raise
        except frida.ProcessNotFoundError:
            raise
        except frida.TransportError:
            raise
        except frida.ProtocolError:
            raise
        except Exception as e:
            raise

    def detach(self):
        """Detaches from the process."""
        if self.session:
            try:
                self.session.detach()
                logger.debug("Frida session detached successfully.")
            except Exception as e:
                logger.warning(f"Error during detachment: {e}")
            finally:
                self.session = None
                self.script = None

    def call_rpc(self, method_name, *args, wait_for_result=True, timeout=10):
        """
        Calls an exported RPC function in the Frida script.

        :param method_name: The name of the RPC function to call.
        :param args: The arguments to pass to the RPC function.
        :param wait_for_result: Whether to wait for the script to return a result via send().
        :param timeout: The timeout in seconds to wait for a result.
        :return: The result from the script if wait_for_result is True, otherwise None.
        """
        if not self.script or not hasattr(self.script.exports, method_name):
            logger.error(f"RPC method '{method_name}' not found in script exports.")
            return None

        # 过滤掉 None 参数，防止传递到 JS 端变成 null
        filtered_args = tuple(a for a in args if a is not None)
        logger.debug(f"Calling RPC method '{method_name}' with args: {filtered_args}")
        self.message_event.clear()
        self.result_data = None
        self.error_occurred = False

        try:
            # Get a reference to the RPC function and call it
            rpc_method = getattr(self.script.exports, method_name)
            rpc_method(*filtered_args)
        except Exception as e:
            logger.error(
                f"Error calling RPC method '{method_name}': {e}", exc_info=True
            )
            if "unable to find method" in str(e).lower():
                logger.error(
                    f"RPC method '{method_name}' not found in the Frida script. "
                    "Please check the JS script's rpc.exports for correct method name and case."
                )
            self.error_occurred = True
            return None

        if wait_for_result:
            logger.debug(f"Waiting for result from '{method_name}'...")
            event_was_set = self.message_event.wait(timeout)
            if self.error_occurred:
                logger.error("An error occurred in the script during RPC execution.")
                return None
            if not event_was_set:
                logger.warning(f"Timed out waiting for result from '{method_name}'.")
                return None
            logger.debug(f"Received result: {self.result_data}")
            return self.result_data
        
        return None

    def run_script(self, target, rpc_calls):
        """
        A complete execution flow: attach, execute a series of RPC calls, and then detach.

        :param target: The process name or PID to attach to.
        :param rpc_calls: A list of tuples, where each tuple contains (method_name, args, wait_for_result).
        :return: The result of the last RPC call that waited for a result.
        """
        last_result = None
        try:
            self.attach(target)
            for method, rpc_args, wait in rpc_calls:
                result = self.call_rpc(method, *rpc_args, wait_for_result=wait)
                if wait:
                    last_result = result
                if self.error_occurred:
                    logger.error("Stopping execution due to script error.")
                    break
        except frida.ServerNotRunningError:
            logger.error("Error: Frida server is not running on the device. Please start it first.")
            self.error_occurred = True
        except frida.ProcessNotFoundError:
            logger.error(f"Process '{target}' not found.")
            self.error_occurred = True
        except frida.TransportError as e:
            logger.error(f"Transport error while communicating with device: {e}")
            self.error_occurred = True
        except frida.ProtocolError as e:
            frida_tool_version = self._get_frida_tool_version()
            frida_server_version = self._get_frida_server_version()
            if frida_tool_version and frida_server_version and frida_tool_version != frida_server_version:
                logger.error(f"Protocol error: Frida tool version ({frida_tool_version}) does not match Frida server version ({frida_server_version}). Please ensure both are the same version.")
            else:
                logger.error(f"Protocol error: {e}")
            self.error_occurred = True
        except Exception as e:
            logger.error(f"An error occurred during the run_script execution: {e}", exc_info=True)
            self.error_occurred = True
        finally:
            self.detach()
        return last_result

