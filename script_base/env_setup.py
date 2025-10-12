#!/usr/bin/env python3

import os
from enum import Enum
from appdirs import user_cache_dir, user_config_dir, user_data_dir
from log import logger

class PathType(Enum):
    CACHE = "cache_files_dir"
    CONFIG = "config"
    DATA = "data"

class EnvSetup:
    """
    Singleton class for environment setup, providing path management with priority: environment variable > appdirs default.
    """
    _instance = None
    _appdirs_map = {
        PathType.CACHE: user_cache_dir,
        PathType.CONFIG: user_config_dir,
        PathType.DATA: user_data_dir,
    }

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not hasattr(self, '_initialized'):
            self._initialized = True

    def get_path(self, path_type: PathType, project_name: str) -> str:
        """
        Get the path for the specified type, with the following priority:
        1. Environment variable
        2. appdirs default path (with a warning log)

        :param path_type: PathType enum
        :param project_name: Project name (used for appdirs)
        :return: Path string
        """
        if not project_name:
            raise ValueError("project_name must not be empty")
        # 1. Environment variable
        env_key = f"{path_type.value}"
        if env_key in os.environ:
            return os.environ[env_key]
        # 2. appdirs
        if path_type not in self._appdirs_map:
            raise ValueError(f"Unknown PathType: {path_type}")
        path = self._appdirs_map[path_type](project_name)
        logger.warning(f"{env_key} not found in environment variable, using appdirs default path: {path}")
        return path

    def setup(self):
        """
        Setup method to initialize the environment.
        """
        logger.info("Environment setup completed.")

    def get(self, path_type: PathType, project_name: str) -> str:
        """
        Alias for get_path method.
        """
        return self.get_path(path_type, project_name)

# Create a singleton instance
env = EnvSetup()

project_name = "android_script"

# test/demo code
if __name__ == "__main__":
    env.setup()  # Initialize environment
    cache_dir = env.get(PathType.CACHE, project_name)  # Or use env.get_path(...)
    config_dir = env.get(PathType.CONFIG, project_name)
    data_dir = env.get(PathType.DATA, project_name)
    logger.info(f"Cache dir: {cache_dir}")
    logger.info(f"Config dir: {config_dir}")
    logger.info(f"Data dir: {data_dir}")
