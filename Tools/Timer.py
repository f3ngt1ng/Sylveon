# -*- coding: UTF-8 -*-


from functools import wraps
from timeit import default_timer as timer

from Tools.Logger import logger


def timeit(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        start_time = timer()
        result = f(*args, **kwargs)
        end_time = timer()

        logger.info("{function_name} took {difference} seconds.").format(
            function_name = f.__name__,
            difference = end_time - start_time
        )

        return result

    return wrapper
