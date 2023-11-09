import sys

from pathlib import Path

sys.path.append(Path(__file__).parent.parent.parent.as_posix())

from models import *


class InitData:
    def init(self) -> None:
        """
        初始化数据
        """

        self.init_user()

    def init_user(self) -> None:
        """
        初始化用户
        """

        data = {
            "admin": {
                "password": "admin1234",
                "role": 1,
                "super_admin": True,
                "enable": True,
            },
            "maintenance": {
                "password": "maintenance1234",
                "role": 2,
                "enable": True,
            },
        }

        for k, v in data.items():
            obj = AdminUser.objects(username=k).first()

            if not obj:
                obj = AdminUser(username=k)

            obj.password = v["password"]
            obj.role = v["role"]
            obj.super_admin = v.get("super_admin", False)
            obj.enable = v["enable"]

            obj.save()


if __name__ == "__main__":
    init = InitData()
    init.init()
