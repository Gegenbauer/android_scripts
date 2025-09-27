#!/usr/bin/env python3
"""
Multi-purpose encoding/decoding tool, supporting utf-8, base64, and url.
"""
import base64
import urllib.parse
import sys
from script_base.script_manager import ScriptManager, Command
from script_base.log import logger

class EncodingStrategy:
    """
    Base class for encoding and decoding strategies.
    """
    def encode(self, text):
        raise NotImplementedError

    def decode(self, text):
        raise NotImplementedError

class UTF8Strategy(EncodingStrategy):
    """
    Strategy for UTF-8 encoding and decoding.
    """
    def encode(self, text):
        return text.encode('utf-8').decode('utf-8', errors='ignore')

    def decode(self, text):
        try:
            return text.encode('latin-1').decode('utf-8')
        except UnicodeDecodeError as e:
            raise ValueError(f"Decoding Error: Incompatible encoding: {e}") from e

class Base64Strategy(EncodingStrategy):
    """
    Strategy for Base64 encoding and decoding.
    """
    def encode(self, text):
        encoded_bytes = base64.b64encode(text.encode('utf-8'))
        return encoded_bytes.decode('utf-8')

    def decode(self, text):
        decoded_bytes = base64.b64decode(text.encode('utf-8'))
        return decoded_bytes.decode('utf-8')

class URLStrategy(EncodingStrategy):
    """
    Strategy for URL encoding and decoding.
    """
    def encode(self, text):
        return urllib.parse.quote(text)

    def decode(self, text):
        return urllib.parse.unquote(text)

def get_encoding_strategy(encoding):
    encoding = encoding.lower()
    if encoding == "utf-8":
        return UTF8Strategy()
    elif encoding == "base64":
        return Base64Strategy()
    elif encoding == "url":
        return URLStrategy()
    else:
        raise ValueError(f"Unsupported encoding: {encoding}")

def read_file_content(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            return f.read().strip()
    except FileNotFoundError as e:
        raise FileNotFoundError(f"File not found: {file_path}") from e
    except IOError as e:
        raise IOError(f"Error reading file: {file_path}: {e}") from e

class EncodeCommand(Command):
    """
    Encodes input text, supporting utf-8, base64, and url.
    """
    def add_arguments(self, parser):
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("--text", type=str, help="The string to encode.")
        group.add_argument("--file", type=str, help="Path to the file containing the content to encode.")
        parser.add_argument("--encoding", type=str, default="utf-8", help="Encoding type, supports utf-8, base64, url. Default is utf-8.")

    def execute(self, args):
        try:
            if args.file:
                text = read_file_content(args.file)
            else:
                text = args.text
            strategy = get_encoding_strategy(args.encoding)
            result = strategy.encode(text)
            print(result)
        except Exception as e:
            logger.error(f"Encoding failed: {e}", exc_info=True)
            sys.exit(1)

class DecodeCommand(Command):
    """
    Decodes input text, supporting utf-8, base64, and url.
    """
    def add_arguments(self, parser):
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("--text", type=str, help="The string to decode.")
        group.add_argument("--file", type=str, help="Path to the file containing the content to decode.")
        parser.add_argument("--encoding", type=str, default="utf-8", help="Decoding type, supports utf-8, base64, url. Default is utf-8.")

    def execute(self, args):
        try:
            if args.file:
                text = read_file_content(args.file)
            else:
                text = args.text
            strategy = get_encoding_strategy(args.encoding)
            result = strategy.decode(text)
            print(result)
        except Exception as e:
            logger.error(f"Decoding failed: {e}", exc_info=True)
            sys.exit(1)

if __name__ == "__main__":
    manager = ScriptManager(description="Multi-purpose encoding/decoding tool, supporting utf-8, base64, and url.\n\nUsage examples:\n  python encoder.py encode --text 'abc' --encoding base64\n  python encoder.py decode --file ./data.txt --encoding url\n")
    manager.register_command("encode", EncodeCommand(), help_text="Encode the input text.")
    manager.register_command("decode", DecodeCommand(), help_text="Decode the input text.")
    manager.run()