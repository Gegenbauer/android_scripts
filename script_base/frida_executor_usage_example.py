#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
from script_base.log import logger
from python_scripts.script_base.frida_utils import FridaScriptExecutor
from android_util_impls.manager import android_util_manager

# Define the Frida script to be used
DUMMY_SCRIPT_FILE = "dummy_frida_script.js"
# Define a target process for demonstration
TARGET_PROCESS = "com.android.settings"

def main():
    """
    Demonstrates how to use the FridaScriptExecutor base class.
    """
    logger.info("--- FridaScriptExecutor Usage Demonstration ---")

    script_dir = os.path.dirname(os.path.abspath(__file__))
    frida_script_path = os.path.join(script_dir, DUMMY_SCRIPT_FILE)

    try:
        # 1. Create a FridaScriptExecutor instance
        #    Pass the path to the Frida script.
        executor = FridaScriptExecutor(frida_script_path)

        android_util = android_util_manager.select()
        pid = android_util.get_pid_of_app(TARGET_PROCESS, executor.device)
        if not pid or pid == -1:
            logger.error(f"Demonstration failed: Could not find process '{TARGET_PROCESS}'. Please ensure it is running.")
            sys.exit(1)

        # --- Demonstration Method A: Manual control of attach and detach ---
        logger.info("\n--- Demonstration A: Manual attach, call, and detach ---")
        
        # 3. Attach to the target process (this will also automatically load the script)
        executor.attach(pid)

        # 4. Call RPC functions
        
        # Example 1: Call a function with a return value
        # `wait_for_result=True` will pause the program until the Frida script `send()`s a result back.
        logger.info("Calling getSomeValue(2) and waiting for the result...")
        result = executor.call_rpc("getSomeValue", 2, wait_for_result=True, timeout=5)
        if result is not None:
            logger.info(f"Python received result: {result}") # Should print 84

        # Example 2: Call a function without a return value (just performs an action)
        # `wait_for_result=False` returns immediately, without waiting for the Frida script. This is a "fire-and-forget" call.
        logger.info("Calling performAction('reboot') without waiting...")
        executor.call_rpc("performAction", "reboot", wait_for_result=False)
        logger.info("Python code continues execution without waiting for JS to finish.")

        # Example 3: Call a function and wait for its completion signal
        # Even if the JS function doesn't return data, we can wait for it to send back a 'finish' signal.
        logger.info("Calling performAction('shutdown') and waiting for it to complete...")
        executor.call_rpc("performAction", "shutdown", wait_for_result=True, timeout=5)
        logger.info("JS script has confirmed the 'shutdown' action is complete.")

        # 5. Detach from the process
        executor.detach()

        # --- Demonstration Method B: Using the high-level run_script method ---
        logger.info("\n--- Demonstration B: Using the high-level run_script method ---")
        
        # The `run_script` method encapsulates the entire attach -> call -> detach flow.
        # It accepts a list containing all RPC calls.
        rpc_calls = [
            # (function_name, (arguments_tuple), wait_for_result)
            ("getSomeValue", (10,), True),
            ("performAction", ("final cleanup",), False)
        ]
        
        logger.info("Executing a batch of RPC calls using run_script...")
        last_result = executor.run_script(pid, rpc_calls)
        logger.info(f"run_script finished. The result of the last awaited call is: {last_result}") # Should print 420

    except FileNotFoundError as e:
        logger.error(str(e), exc_info=True)
        sys.exit(1)
    except Exception as e:
        logger.error(f"An unexpected error occurred during the demonstration: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
