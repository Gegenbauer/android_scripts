#!/usr/bin/env python3

# 确认 pip3 是否安装
# which pip3
# 如果没有安装
# sudo apt update
# sudo apt install python3-pip
# 确认虚拟环境是否安装
# which python3-venv
# 如果没有安装
# sudo apt install python3-venv

if __name__ == "__main__":
    import os
    tools_dir = os.environ.get('tools_dir', '')
    target_dir = os.path.join(tools_dir, 'py_virtual_envs', 'scripts')
    if not os.path.exists(target_dir):
        # create use venv
        os.makedirs(target_dir, exist_ok=True)
        os.system(f'python -m venv {target_dir}')
    print('source $tools_dir/py_virtual_envs/scripts/bin/activate')