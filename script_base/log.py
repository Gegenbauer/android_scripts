import logging
import sys

try:
    from colorlog import ColoredFormatter
    _USE_COLOR = True
except ImportError:
    _USE_COLOR = False

class Logger:
    """
    基于标准 logging 的单例日志器，支持自定义格式和异常堆栈。
    """
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(Logger, cls).__new__(cls)
        return cls._instance

    def __init__(self, level=logging.INFO):
        if hasattr(self, '_initialized'):
            return
        self.logger = logging.getLogger("project_logger")
        self.logger.propagate = False
        self.set_level(level)
        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            if _USE_COLOR:
                formatter = ColoredFormatter(
                    "%(log_color)s[%(asctime)s] [%(levelname)s] %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                    log_colors={
                        'DEBUG':    'cyan',
                        'INFO':     'green',
                        'WARNING':  'yellow',
                        'ERROR':    'red',
                        'CRITICAL': 'bold_red',
                    }
                )
            else:
                formatter = logging.Formatter(
                    "[%(asctime)s] [%(levelname)s] %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S"
                )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        self._initialized = True

    def set_level(self, level):
        self.logger.setLevel(level)

    def debug(self, message, *args, **kwargs):
        self.logger.debug(message, *args, **kwargs)

    def info(self, message, *args, **kwargs):
        self.logger.info(message, *args, **kwargs)

    def warning(self, message, *args, **kwargs):
        self.logger.warning(message, *args, **kwargs)

    def error(self, message, exc=None, *args, **kwargs):
        if exc:
            self.logger.error(message, exc_info=exc, *args, **kwargs)
        else:
            self.logger.error(message, *args, **kwargs)

# 创建一个全局 logger 实例
logger = Logger()

# test
if __name__ == "__main__":
    logger.info("This is an info message.")
    logger.warning("This is a warning message.")
    logger.error("This is an error message.")
    logger.debug("This is a debug message.")