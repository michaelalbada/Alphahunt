import logging

def setup_logging(debug=False, log_to_file=None):
    """
    Set up logging for the application.
    :param debug: If True, set level to DEBUG, else INFO.
    :param log_to_file: If provided, also log to the specified file.
    """
    level = logging.DEBUG if debug else logging.INFO
    handlers = [logging.StreamHandler()]
    if log_to_file:
        handlers.append(logging.FileHandler(log_to_file))
    logging.basicConfig(
        level=level,
        format='[%(asctime)s] %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=handlers
    )

class BaseLogger:
    def __init__(self, logger_name=None):
        import logging
        self.logger = logging.getLogger(logger_name or self.__class__.__name__)
        if not self.logger.hasHandlers():
            handler = logging.StreamHandler()
            formatter = logging.Formatter('[%(asctime)s] %(levelname)s %(name)s: %(message)s', '%Y-%m-%d %H:%M:%S')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

    def log_info(self, msg):
        self.logger.info(msg)

    def log_warning(self, msg):
        self.logger.warning(msg)

    def log_error(self, msg):
        self.logger.error(msg) 