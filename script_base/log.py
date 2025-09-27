import logging
import sys

try:
    from colorlog import ColoredFormatter
    _USE_COLOR = True
except ImportError:
    _USE_COLOR = False

class Logger:
    """
    Logger based on standard logging, supporting custom format and exception stack trace.
    Each Logger instance is independent and can have its own format.
    """
    def __init__(self, level=logging.DEBUG, simple=False, name=None):
        # Use a unique logger name if not specified, to avoid handler/formatter sharing
        if name is None:
            name = f"project_logger_{id(self)}"
        self.logger = logging.getLogger(name)
        self.logger.propagate = False
        self.set_level(level)
        # Remove all handlers to ensure formatter is always set as requested
        while self.logger.handlers:
            self.logger.handlers.pop()
        handler = logging.StreamHandler(sys.stdout)
        if simple:
            if _USE_COLOR:
                formatter = ColoredFormatter(
                    "%(log_color)s%(message)s",
                    log_colors={
                        'DEBUG':    'cyan',
                        'INFO':     'green',
                        'WARNING':  'yellow',
                        'ERROR':    'red',
                        'CRITICAL': 'bold_red',
                    }
                )
            else:
                formatter = logging.Formatter("%(message)s")
        else:
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
        self._simple = simple

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

    @property
    def simple(self):
        return self._simple

# Create a global logger instance
logger = Logger()
simple_logger = Logger(simple=True)

# test
if __name__ == "__main__":
    logger.info("This is an info message.")
    logger.warning("This is a warning message.")
    logger.error("This is an error message.")
    logger.debug("This is a debug message.")
    simple_logger.info("This is a simple info message.")
    print(f"simple_logger.simple: {simple_logger.simple}")
    print(f"logger.simple: {logger.simple}")
