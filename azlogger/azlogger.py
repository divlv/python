##########################################################################################################
"""
AzurePoweredLogger Library

Description:
This library provides a custom logger that logs messages to both the console and Azure Monitor Log Workspace.
It includes buffering and flush mechanisms to minimize network usage and supports optional per-message control
over whether logs are sent to Azure Monitor. Additionally, it supports logging to a local file with rotation.

Features:
- Logs messages at different levels: INFO, DEBUG, WARN, ERROR, CRITICAL.
- Buffers log messages and flushes them to Azure Monitor based on buffer size or time interval.
- Option to override the default logging to Azure behavior for individual messages.
- Option to log messages to a local file with rotation.
- Logs are sent to the console, Azure Monitor, and optionally to a file.

Sample Usage:
    from myloggerpythonfile import AzurePoweredLogger

    def main():
        logger = AzurePoweredLogger()

        try:
            logger.info("Application started")
            logger.debug("Performing some debug operations")
            logger.warning("This is a warning example")
            logger.error("This is an error example")
            logger.critical("This is a critical example")

            # Force not logging a specific message to Azure
            logger.info("This message will not be logged to Azure", do_not_log_to_azure=True)
        finally:
            logger.close()

    if __name__ == "__main__":
        main()
"""

import logging
import os
import logging.handlers
import datetime
import uuid
import json
import base64
import hashlib
import hmac
import requests
import socket
import time

workspace_id = "6fd5-ENTER-GUID-OF-YOUR-WORKSPACE-5bf11f"
shared_key = "KhGBEyx_ENTER_SHARED_KEY_OF_YOUR_AZURE_LOGANALYTICS_WORKSPACE_AVUF8bMfgQ=="
log_name = "PythontestLog"  # Target table name in Azure Monitor = PythontestLog_CL

# Buffer and flush settings
buffer_size = 10  # Number of log entries to buffer before sending
flush_interval = 5  # Time in seconds to flush the buffer

# Default setting for logging to Azure
logging_to_Azure = True  # If True, logs are sent to Azure Monitor

# Set up the logger
logging.basicConfig(level=logging.DEBUG)
azure_powered_logger_internal = logging.getLogger()

# Suppress logs from certain libraries
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)

# Configuration settings for Azure Monitor logging
log_filename = "python.log"  # Log file name
log_to_file = False  # Boolean switch to log to file or not

# Ensure the log file is created in the directory of the main script
script_dir = os.path.dirname(os.path.abspath(__file__))
log_filepath = os.path.join(script_dir, log_filename)

if log_to_file:
    # Set up file handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        log_filepath, maxBytes=10 * 1024 * 1024, backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)

    # Create a formatter and set it for both handlers
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    file_handler.setFormatter(formatter)
    azure_powered_logger_internal.addHandler(file_handler)


# Logs to be sent as HTTP output
function_output = ""

# Unique Job ID for the current job
job_id = str(uuid.uuid4())


class AzurePoweredLogger:
    def __init__(self):
        """Initialize the AzurePoweredLogger with an empty log buffer and record the last flush time."""
        self.log_buffer = []
        self.last_flush_time = time.time()

    def current_time_with_milliseconds(self):
        """Get the current time formatted with milliseconds."""
        now = datetime.datetime.now(datetime.timezone.utc)
        return now.strftime("%H:%M:%S") + f".{now.microsecond // 1000:03}"

    def create_signature(self, date, content_length):
        """Create a signature for the Azure Monitor HTTP request."""
        string_to_hash = (
            f"POST\n{content_length}\napplication/json\nx-ms-date:{date}\n/api/logs"
        )
        # Ensure the shared key is correctly padded
        shared_key_padded = shared_key + "=" * (4 - len(shared_key) % 4)
        decoded_key = base64.b64decode(shared_key_padded)
        bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
        encoded_hash = base64.b64encode(
            hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
        ).decode()
        authorization = f"SharedKey {workspace_id}:{encoded_hash}"
        return authorization

    def log_to_azure(self, json_payload):
        """Send the log payload to Azure Monitor."""
        rfc1123date = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%a, %d %b %Y %H:%M:%S GMT"
        )
        content_length = len(json_payload)
        signature = self.create_signature(rfc1123date, content_length)
        uri = f"https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"

        headers = {
            "Content-Type": "application/json",
            "Authorization": signature,
            "Log-Type": log_name,
            "x-ms-date": rfc1123date,
        }

        response = requests.post(uri, data=json_payload, headers=headers)
        if response.status_code >= 200 and response.status_code <= 299:
            azure_powered_logger_internal.info(
                f"Logging data successfully posted to Azure Monitor. Response code: {response.status_code}"
            )
        else:
            azure_powered_logger_internal.error(
                f"Failed to post logging data to Azure Monitor. Response code: {response.status_code}, Response: {response.text}"
            )

    def flush_buffer(self):
        """Flush the log buffer to Azure Monitor."""
        if self.log_buffer:
            json_payload = json.dumps(self.log_buffer)
            self.log_to_azure(json_payload)
            self.log_buffer = []
            self.last_flush_time = time.time()

    def get_computer_name(self):
        """Get the name of the computer."""
        try:
            return socket.gethostname()
        except Exception as e:
            azure_powered_logger_internal.error(
                f"Error getting computer name: {str(e)}"
            )
            return "unknown"

    def log(self, level, msg, do_not_log_to_azure=None):
        """Log a message at the specified level and optionally override the default Azure logging behavior."""
        ctime = self.current_time_with_milliseconds()
        log_msg = f"### {ctime} {level} JobId:{job_id} - {msg}"
        json_payload = {
            "LogLevel": level,
            "JobId": job_id,
            "Message": msg,
            "Timestamp": ctime,
            "ComputerName": self.get_computer_name(),
        }

        if level == "INFO":
            azure_powered_logger_internal.info(log_msg)
        elif level == "DEBUG":
            azure_powered_logger_internal.debug(log_msg)
        elif level == "WARN":
            azure_powered_logger_internal.warning(log_msg)
        elif level == "ERROR":
            azure_powered_logger_internal.error(log_msg)
        elif level == "CRITICAL":
            azure_powered_logger_internal.critical(log_msg)

        log_to_azure = (
            logging_to_Azure if do_not_log_to_azure is None else not do_not_log_to_azure
        )

        if log_to_azure:
            self.log_buffer.append(json_payload)
            current_time = time.time()
            if (
                len(self.log_buffer) >= buffer_size
                or (current_time - self.last_flush_time) >= flush_interval
            ):
                self.flush_buffer()

        global function_output
        function_output = function_output + log_msg + "\n"

    def info(self, msg, do_not_log_to_azure=None):
        """Log an info message."""
        self.log("INFO", msg, do_not_log_to_azure)

    def debug(self, msg, do_not_log_to_azure=None):
        """Log a debug message."""
        self.log("DEBUG", msg, do_not_log_to_azure)

    def warning(self, msg, do_not_log_to_azure=None):
        """Log a warning message."""
        self.log("WARN", msg, do_not_log_to_azure)

    def error(self, msg, do_not_log_to_azure=None):
        """Log an error message."""
        self.log("ERROR", msg, do_not_log_to_azure)

    def critical(self, msg, do_not_log_to_azure=None):
        """Log a critical message."""
        self.log("CRITICAL", msg, do_not_log_to_azure)

    def close(self):
        """Flush the buffer when closing the logger."""
        self.flush_buffer()


##########################################################################################################
