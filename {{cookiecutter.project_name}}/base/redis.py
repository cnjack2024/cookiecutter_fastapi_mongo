import json

import config
import redis

from types import TracebackType
from typing import Any, Callable, Self


class Redis:
    connection_pool = redis.ConnectionPool.from_url(
        config.REDIS_URL, db=0, decode_responses=True
    )

    def __init__(self):
        self.conn = redis.Redis(connection_pool=self.connection_pool)

    def get(self, name: str) -> Any:
        """
        获取
        """

        data = self.conn.get(self.__key__(name))

        if data:
            data = json.loads(data)

        return data

    def set(self, name: str, data: Any, expire: int | None = None) -> bool:
        """
        设置
        """

        return self.conn.set(self.__key__(name), json.dumps(data), expire)

    def delete(self, name: str, match: bool = False) -> int:
        """
        删除
        """

        if match:
            keys = [key for key in self.conn.scan_iter(self.__key__(name))]

            if keys:
                return self.conn.delete(*keys)

            return 0
        else:
            return self.conn.delete(self.__key__(name))

    def cache(self, name: str, func: Callable, *args: Any, **kwargs: Any) -> Any:
        """
        从缓存中获取
        """

        name = self.__cache_name__(name)

        data = self.get(name)

        if data:
            return data

        data = func(*args)

        self.set(name, data, kwargs.get("expire") or config.REDIS_CACHE_EXPIRED)

        return data

    def delete_cache(self, name: str) -> int:
        """
        删除缓存
        """

        return self.delete(self.__cache_name__(name))

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.conn.close()

    def __key__(self, name: str) -> str:
        """
        Key
        """

        return ":".join((config.REDIS_NAME, name))

    def __cache_name__(self, name: str) -> str:
        """
        缓存Key
        """

        return ":".join(("cache", name))
