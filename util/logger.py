import logging


def __setup_logger(log_level=logging.INFO):
    logger = logging.getLogger(__name__)
    logger.setLevel(log_level)
    formatter = logging.Formatter('%(levelname)s: "%(message)s"')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


Logger = __setup_logger()  # Default log level is INFO

# Change the log level to DEBUG
Logger.setLevel(logging.DEBUG)

