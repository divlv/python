# Python
Helper libraries and functions for Python development



# AzurePoweredLogger

AzurePoweredLogger is a custom Python logging library that allows you to log messages to the console, Azure Monitor Log Workspace, and optionally to a local file with rotation. It includes buffering mechanisms to optimize network usage when sending logs to Azure.

## 1. Features

- **Multiple Logging Levels:** Log messages at INFO, DEBUG, WARN, ERROR, and CRITICAL levels.
- **Buffering:** Log messages are buffered and flushed to Azure Monitor based on buffer size or time intervals.
- **Selective Azure Logging:** Override the default behavior to control whether individual messages are sent to Azure Monitor.
- **File Logging:** Option to log messages to a local file with automatic rotation.


## 2. Usage

Here is a basic example of how to use the AzurePoweredLogger:

```python
from azlogger import AzurePoweredLogger

def main():
    logger = AzurePoweredLogger()
    logger.info("This is an info message")
    logger.error("This is an error message")
    # Add more logging as needed
```

## 3. Configuration

You can configure various aspects of the logger, such as:

- **Buffer Size:** Adjust the size of the message buffer before flushing to Azure.
- **Flush Interval:** Set a time interval for automatic flushing.
- **File Logging:** Enable and configure log file paths and rotation settings.

## 4. License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 5. Contributing

Feel free to submit issues or pull requests. For major changes, please open an issue first to discuss what you would like to change.

## 6. Acknowledgements

This library was developed with the aim to simplify logging to Azure Monitor and improve performance with buffered logging.
