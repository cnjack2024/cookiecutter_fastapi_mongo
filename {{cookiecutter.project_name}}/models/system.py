import casbin

from base.models import *
from base.redis import Redis


class Menu(Document):
    """
    菜单
    """

    id = ObjectIdField(primary_key=True, default=bson.ObjectId, verbose_name="ID")
    scope = StringField(
        max_length=64, required=True, default="admin", verbose_name="SCOPE"
    )
    name = StringField(
        max_length=64, required=True, unique_with=["scope"], verbose_name="菜单名称"
    )
    code = StringField(max_length=64, required=True, unique=True, verbose_name="菜单代码")
    path = StringField(
        max_length=128, required=True, unique_with=["scope"], verbose_name="菜单路径"
    )
    title = StringField(max_length=64, required=True, verbose_name="菜单标题")
    icon = StringField(max_length=64, null=True, verbose_name="菜单图标")
    prefix = StringField(max_length=254, null=True, verbose_name="关联API前缀")

    def validate_data(self) -> None:
        """
        数据校验
        """

        if not self.code:
            raise HTTPException(
                detail="菜单代码不能为空",
                status_code=HTTP_400_BAD_REQUEST,
            )

        if len(self.code) % 4 != 0:
            raise HTTPException(
                detail="菜单代码长度错误(长度必须是4的倍数)",
                status_code=HTTP_400_BAD_REQUEST,
            )

        obj = Menu.objects(code=self.code).first()

        if obj and obj.id != self.id:
            raise HTTPException(
                detail="菜单代码已存在",
                status_code=HTTP_400_BAD_REQUEST,
            )

        if len(self.code) > 4:
            obj = Menu.objects(code=self.code[:-4]).first()

            if not obj:
                raise HTTPException(
                    detail=f"上级菜单不存在(菜单代码: {self.code[:-4]})",
                    status_code=HTTP_400_BAD_REQUEST,
                )

        obj = Menu.objects(scope=self.scope, name=self.name).first()

        if obj and obj.id != self.id:
            raise HTTPException(
                detail="菜单名称已存在",
                status_code=HTTP_400_BAD_REQUEST,
            )

        obj = Menu.objects(scope=self.scope, path=self.path).first()

        if obj and obj.id != self.id:
            raise HTTPException(
                detail="菜单路径已存在",
                status_code=HTTP_400_BAD_REQUEST,
            )

        self.prefix = self.prefix.rstrip("*").rstrip("/")

    def children(self, all: bool = False) -> list[Self]:
        """
        子菜单
        """

        objs = []

        queryset = Menu.objects(code != self.code, code__startswith=self.code)

        if not all:
            queryset = queryset.where(f"this.code.length=={len(self.code) + 4}")

        for obj in queryset.order_by("code"):
            objs.append(obj)

        return objs

    def enforce(self, auth_user: Any) -> tuple[bool, bool, bool, bool]:
        """
        权限检查
        """

        GET = False
        POST = False
        PUT = False
        DELETE = False

        if self.prefix:
            if auth_user.super_admin:
                GET = True
                POST = True
                PUT = True
                DELETE = True
            else:
                for obj in PermissionRule.objects(
                    scope=self.scope,
                    role__in=auth_user.get_current_roles(),
                    menu=self,
                ):
                    if obj.GET:
                        GET = True

                    if obj.POST:
                        POST = True

                    if obj.PUT:
                        PUT = True

                    if obj.DELETE:
                        DELETE = True

        return GET, POST, PUT, DELETE


class PermissionRule(Document):
    """
    权限策略
    """

    id = ObjectIdField(primary_key=True, default=bson.ObjectId, verbose_name="ID")
    scope = StringField(
        max_length=64, required=True, unique_with=["role", "path"], verbose_name="SCOPE"
    )
    role = ObjectIdField(required=True, verbose_name="角色")
    path = StringField(max_length=128, required=True, verbose_name="路径")
    menu = ReferenceField(
        Menu,
        reverse_delete_rule=mongoengine.CASCADE,
        null=True,
        verbose_name="菜单",
    )

    GET = BooleanField(default=False, verbose_name="GET操作")
    POST = BooleanField(default=False, verbose_name="POST操作")
    PUT = BooleanField(default=False, verbose_name="PUT操作")
    DELETE = BooleanField(default=False, verbose_name="DELETE操作")

    meta = {
        "indexes": [
            "menu",
        ]
    }

    def validate_data(self) -> None:
        """
        数据校验
        """

        if not self.menu:
            raise HTTPException(
                detail="未知菜单",
                status_code=HTTP_400_BAD_REQUEST,
            )

        if not self.menu.prefix:
            raise HTTPException(
                detail="菜单设置错误",
                status_code=HTTP_400_BAD_REQUEST,
            )

        self.scope = self.menu.scope
        self.path = self.menu.prefix

        obj = PermissionRule.objects(
            scope=self.scope, role=self.role, path=self.path
        ).first()

        if obj and obj.id != self.id:
            raise HTTPException(
                detail="权限策略已存在",
                status_code=HTTP_400_BAD_REQUEST,
            )

        with Redis() as conn:
            conn.delete_cache(self.__class__.__name__.lower())

    def policy(self):
        CRUD = []

        for name, value in (
            ("GET", self.GET),
            ("POST", self.POST),
            ("PUT", self.PUT),
            ("DELETE", self.DELETE),
        ):
            if not value:
                continue

            CRUD.append(name)

        data = []

        if CRUD:
            sub = f"{self.scope}:{self.role}"

            if len(CRUD) > 1:
                act = "|".join([f"({x})" for x in CRUD])
            else:
                act = CRUD[0]

            for path in (self.path, self.path + "/*"):
                data.append(", ".join(("p", sub, path, act)))

        return data

    @classmethod
    def enforcer(cls) -> casbin.Enforcer:
        """
        权限检查器
        """

        class Adapter(casbin.persist.Adapter):
            def load_policy(self, model):
                def get_data():
                    data = []

                    for obj in PermissionRule.objects:
                        data += obj.policy()

                    return data

                with Redis() as conn:
                    data = conn.cache(cls.__name__.lower(), get_data, expire=30 * 60)

                    for policy in data:
                        casbin.persist.load_policy_line(policy, model)

        m = casbin.Model()
        m.load_model_from_text(
            """
                [request_definition]
                r = sub, obj, act

                [policy_definition]
                p = sub, obj, act

                [policy_effect]
                e = some(where (p.eft == allow))

                [matchers]
                m = r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act) || r.sub == "admin"
            """
        )

        return casbin.Enforcer(m, Adapter())

    @classmethod
    def enforce(
        cls, enforcer: casbin.Enforcer, subs: list[str], obj: str, act: str
    ) -> bool:
        """
        权限检查
        """

        for sub in subs:
            if enforcer.enforce(sub, obj, act):
                return True

        return False
