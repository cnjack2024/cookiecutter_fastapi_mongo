import functools
import hashlib

import config

from typing import Any, Callable

from celery import Celery as _Celery
from celery.result import AsyncResult


class Celery(_Celery):
    def __init__(self):
        CELERY_REDIS_URL = "{}/{}".format(config.REDIS_URL, 1)

        super().__init__(
            backend=CELERY_REDIS_URL,
            broker=CELERY_REDIS_URL,
            broker_connection_retry_on_startup=False,
        )

    def delay(self, name: str, *args, **kwargs) -> AsyncResult:
        """
        调用task
        """

        return self.send_task(name, args, kwargs)

    def mutex(self, func: Callable) -> Any:
        """
        互斥
        """

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            conn = self.backend.client
            key = "{}:celery:mutex:{}:{}".format(
                config.REDIS_NAME,
                func.__name__,
                hashlib.sha256((kwargs.get("key") or f"{args}").encode()).hexdigest(),
            )

            if conn.get(key):
                return None

            try:
                conn.set(key, 1, 60 * 60)
                data = func(*args)
            finally:
                conn.delete(key)

            return data

        return wrapper
