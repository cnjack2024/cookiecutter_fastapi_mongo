from base.models import *


class AdminUser(Document):
    """
    管理员
    """

    ROLE_CHOICES = (
        (1, "系统管理员"),
        (2, "运维人员"),
    )

    id = ObjectIdField(primary_key=True, default=bson.ObjectId, verbose_name="ID")
    username = StringField(
        max_length=64, required=True, unique=True, verbose_name="用户名"
    )
    password = PasswordField(required=True, verbose_name="密码")
    role = ChoiceField(ROLE_CHOICES, default=1, verbose_name="角色")
    super_admin = BooleanField(default=False, verbose_name="是否超级用户")
    enable = BooleanField(default=False, verbose_name="启用")

    create_time = DateTimeField(default=now, verbose_name="创建时间")

    meta = {
        "indexes": [
            "role",
            "super_admin",
            "enable",
        ]
    }

    def validate_data(self) -> None:
        """
        数据校验
        """

        obj = AdminUser.objects(username=self.username).first()

        if obj and obj.id != self.id:
            raise HTTPException(
                detail="用户名已存在",
                status_code=HTTP_400_BAD_REQUEST,
            )

    def get_current_roles(self) -> list[int]:
        """
        当前角色
        """

        return [self.role.code]
