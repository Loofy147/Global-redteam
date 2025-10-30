import logging
import sys

# Create a logger instance
logger = logging.getLogger("global_red_team")
logger.setLevel(logging.INFO)

# Create a handler to output to the console
handler = logging.StreamHandler(sys.stdout)

# Create a formatter and set it for the handler
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
handler.setFormatter(formatter)

# Add the handler to the logger
logger.addHandler(handler)
