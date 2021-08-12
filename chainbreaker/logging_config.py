import logging


DEFAULTS = {
    'loglevel': 'INFO',
}

LOGGER = logging.getLogger('Chainbreaker')
LOGGER.setLevel('INFO')
FORMATTER = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
CONSOLE_HANDLER = logging.StreamHandler()
CONSOLE_HANDLER.setLevel(logging.INFO)
CONSOLE_HANDLER.setFormatter(FORMATTER)
LOGGER.addHandler(CONSOLE_HANDLER)

#
# def setup_logging(args):
#     logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s',
#                         level=args.loglevel,
#                         stream=sys.stdout)
