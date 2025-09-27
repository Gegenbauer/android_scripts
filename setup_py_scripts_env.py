#!/usr/bin/env python3

# Check if pip3 is installed
# which pip3
# If not installed:
# sudo apt update
# sudo apt install python3-pip
# Check if virtual environment is installed
# which python3-venv
# If not installed:
# sudo apt install python3-venv

if __name__ == "__main__":
    import os
    tools_dir = os.environ.get('tools_dir', '')
    target_dir = os.path.join(tools_dir, 'py_virtual_envs', 'scripts')
    if not os.path.exists(target_dir):
        # create using venv
        os.makedirs(target_dir, exist_ok=True)
        os.system(f'python -m venv {target_dir}')
    print('source $tools_dir/py_virtual_envs/scripts/bin/activate')