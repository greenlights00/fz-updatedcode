import requests
import logging
import os
from urllib.parse import urlparse, urlunparse


def url_validate_and_normalize(url: str) -> str:
    """
    Validates and normalizes a URL. Raises ValueError if invalid.
    """
    parsed = urlparse(url)
    if not parsed.scheme:
        url = 'https://' + url
        parsed = urlparse(url)
    if not parsed.netloc:
        raise ValueError(f"Invalid URL: {url}")
    # Remove trailing slash, normalize
    normalized = urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip('/'), '', '', ''))
    return normalized


def load_wordlist(path: str) -> list:
    """
    Loads a wordlist from file, returns a list of lines.
    """
    if not path or not os.path.exists(path):
        raise FileNotFoundError(f"Wordlist not found: {path}")
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f if line.strip()]


def http_request(method, url, retries=2, timeout=10, logger=None, **kwargs):
    """
    Wrapper for requests with retries and error logging.
    """
    for attempt in range(retries):
        try:
            resp = requests.request(method, url, timeout=timeout, **kwargs)
            return resp
        except Exception as e:
            if logger:
                logger.error(f"HTTP {method} {url} failed (attempt {attempt+1}): {e}")
            if attempt == retries - 1:
                return None


def setup_shared_logger(log_file: str):
    """
    Sets up a logger that writes to the specified log file.
    """
    logger = logging.getLogger(log_file)
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    return logger


def log_error(logger, msg: str):
    """
    Logs an error message using the provided logger.
    """
    if logger:
        logger.error(msg) 