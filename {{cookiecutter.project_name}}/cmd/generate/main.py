import sys

from pathlib import Path

sys.path.append(Path(__file__).parent.parent.parent.as_posix())

import click
import jinja2

from base.util import snake_case
from config import BASE_DIR
from models import *


class Generate:
    @staticmethod
    def get_document(name: str) -> Document | None:
        """
        获取文档
        """

        document = None

        try:
            document = mongoengine.base.get_document(name)
        except Exception:
            pass

        return document

    @click.command("document")
    @click.argument("name")
    @click.argument("description")
    @staticmethod
    def document(name: str, description: str) -> None:
        """
        生成文档
        """

        STRING = '''
            from base.models import *


            class {{ name }}(Document):
                """
                {{ description }}
                """

                id = ObjectIdField(primary_key=True, default=bson.ObjectId, verbose_name="ID")
                name = StringField(max_length=64, required=True, verbose_name="名称")

                update_by = StringField(max_length=64, null=True, verbose_name="更新人")
                update_time = DateTimeField(null=True, verbose_name="更新时间")
                create_by = StringField(max_length=64, required=True, verbose_name="创建人")
                create_time = DateTimeField(default=now, verbose_name="创建时间")
                description = StringField(null=True, verbose_name="备注")

                meta = {
                    "indexes": [
                        "name",
                    ]
                }

                def validate_data(self) -> None:
                    """
                    数据校验
                    """
        '''

        content = jinja2.Template(STRING).render(name=name, description=description)
        content = "\n".join([x[12:].rstrip() for x in content.splitlines()]).strip()

        click.echo(content)

    @click.command("relationship_document")
    @click.argument("document")
    @click.argument("secondary_document")
    @staticmethod
    def relationship_document(document: str, secondary_document: str) -> None:
        """
        生成关联文档
        """

        STRING = '''
            from base.models import *


            class {{ document.__name__ }}{{ secondary_document.__name__ }}(Document):
                """
                {{ description }}关联{{ secondary_description }}
                """

                id = ObjectIdField(primary_key=True, default=bson.ObjectId, verbose_name="ID")
                {{ name }} = ReferenceField(
                    {{ document.__name__ }},
                    required=True,
                    unique_with=["{{ secondary_name }}"],
                    reverse_delete_rule=mongoengine.CASCADE,
                    verbose_name="{{ description }}",
                )
                {{ secondary_name }} = ReferenceField(
                    {{ secondary_document.__name__ }},
                    required=True,
                    reverse_delete_rule=mongoengine.CASCADE,
                    verbose_name="{{ secondary_description }}",
                )
        '''

        document_obj = Generate.get_document(document)

        if not document_obj:
            raise click.ClickException(f"未知文档: {document}")

        description = (document_obj.__doc__ or "").strip().splitlines()[0]

        secondary_document_obj = Generate.get_document(secondary_document)

        if not secondary_document_obj:
            raise click.ClickException(f"未知文档: {secondary_document}")

        secondary_description = (
            (secondary_document_obj.__doc__ or "").strip().splitlines()[0]
        )

        content = jinja2.Template(STRING).render(
            name=snake_case(document_obj.__name__),
            document=document_obj,
            description=description,
            secondary_name=snake_case(secondary_document_obj.__name__),
            secondary_document=secondary_document_obj,
            secondary_description=secondary_description,
        )
        content = "\n".join([x[12:].rstrip() for x in content.splitlines()]).strip()

        click.echo(content)

    @click.command("schema")
    @click.argument("document")
    @staticmethod
    def schema(document: str) -> None:
        """
        生成schema
        """

        STRING = '''
            from base.schemas import *
            from models import *


            # ----------------------------------------------------------
            #
            # {{ prefix_description }}
            #
            # ----------------------------------------------------------


            class {{ document.__name__ }}PaginationModel(BaseModel):
                """
                {{ description }}分页信息
                """

                {% for name, typename, required, foreignkey, blank in info -%}
                {% if foreignkey -%}
                {% if required -%}
                {{ name }}: NameModel | None = None
                {%- else -%}
                {{ name }}: NameModel | None = None
                {%- endif %}
                {%- else -%}
                {% if required -%}
                {{ name }}: {{ typename }}
                {%- else -%}
                {{ name }}: {{ typename }} | None = None
                {%- endif %}
                {%- endif %}
                {% if blank %}
                {% endif %}
                {%- endfor %}
                def update(self, obj: Any) -> None:
                    """
                    更新数据
                    """

                    {% for name, required, foreignkey, description, blank in foreignkey_info -%}
                    {% if required -%}
                    self.{{ name }} = NameModel.from_obj(obj.{{ name }})
                    {%- else -%}
                    if obj.{{ name }}:
                        self.{{ name }} = NameModel.from_obj(obj.{{ name }})
                    {%- endif %}
                    {% if blank %}
                    {% endif %}
                    {%- endfor %}

            class {{ document.__name__ }}Model({{ document.__name__ }}PaginationModel):
                """
                {{ description }}信息
                """

                def update(self, obj: Any) -> None:
                    """
                    更新数据
                    """

                    super().update(obj)


            class {{ document.__name__ }}CreateModel(BaseModel):
                """
                新建{{ description }}
                """

                {% for name, typename, required, foreignkey, blank in update_info -%}
                {% if foreignkey -%}
                {% if required -%}
                {{ name }}: {{ typename }}
                {%- else -%}
                {{ name }}: {{ typename }} | None = None
                {%- endif %}
                {%- else -%}
                {% if required -%}
                {{ name }}: {{ typename }}
                {%- else -%}
                {{ name }}: {{ typename }} | None = None
                {%- endif %}
                {%- endif %}
                {% if blank %}
                {% endif %}
                {%- endfor %}
                def update(self, obj: Any) -> None:
                    """
                    更新数据
                    """
                    {% for name, required, foreignkey, description, blank in foreignkey_info %}
                    {% if required -%}
                    {{ name }} = {{ foreignkey.__name__ }}.objects(id=self.{{ name }}).first()

                    if not {{ name }}:
                        raise HTTPException(
                            detail="未知{{ description }}",
                            status_code=HTTP_400_BAD_REQUEST,
                        )

                    obj.{{ name }} = {{ name }}
                    {%- else -%}
                    if self.{{ name }}:
                        {{ name }} = {{ foreignkey.__name__ }}.objects(id=self.{{ name }}).first()

                        if not {{ name }}:
                            raise HTTPException(
                                detail="未知{{ description }}",
                                status_code=HTTP_400_BAD_REQUEST,
                            )

                        obj.{{ name }} = {{ name }}
                    {%- endif %}
                    {% endfor %}

            class {{ document.__name__ }}UpdateModel({{ document.__name__ }}CreateModel):
                """
                更新{{ description }}
                """

                def update(self, obj: Any) -> None:
                    """
                    更新数据
                    """

                    super().update(obj)
        '''

        document_obj = Generate.get_document(document)

        if not document_obj:
            raise click.ClickException(f"未知文档: {document}")

        if not (document_obj.__doc__ or "").strip().splitlines():
            raise Exception("未填写文档注释, 生成失败")

        fields = {}

        for k, v in document_obj._fields.items():
            typename = None
            required = v.required
            foreignkey = None
            primarykey = v.primary_key

            if v.default is not None:
                required = True

            if isinstance(v, ObjectIdField | StringField | UUIDField):
                typename = "str"
            elif isinstance(v, IntField):
                typename = "int"
            elif isinstance(v, FloatField):
                typename = "float"
            elif isinstance(v, BooleanField):
                typename = "bool"
            elif isinstance(v, BinaryField):
                typename = "bytes"
            elif isinstance(v, ChoiceField):
                typename = "ChoiceModel"
            elif isinstance(v, DecimalField | Decimal128Field):
                typename = "decimal.Decimal"
            elif isinstance(v, DateField):
                typename = "datetime.date"
            elif isinstance(v, DateTimeField):
                typename = "DateTimeType"
            elif isinstance(v, ListField):
                if isinstance(v.field, StringField):
                    typename = "list[str]"
                elif isinstance(v.field, IntField):
                    typename = "list[int]"
                elif isinstance(v.field, FloatField):
                    typename = "list[float]"
                elif isinstance(v.field, ChoiceField):
                    typename = "list[ChoiceModel]"
                else:
                    typename = "list"
            elif isinstance(v, DictField):
                typename = "dict"
            elif isinstance(v, EnumField):
                typename = "str | int"
            elif isinstance(v, SequenceField):
                typename = "list"
            elif isinstance(v, GeoPointField):
                typename = "tuple[float, float]"
            elif isinstance(
                v,
                EmbeddedDocumentField
                | GenericEmbeddedDocumentField
                | DynamicField
                | GeoJsonBaseField,
            ):
                typename = "dict"
            elif isinstance(
                v,
                ReferenceField
                | CachedReferenceField
                | GenericReferenceField
                | LazyReferenceField,
            ):
                typename = "str"
                foreignkey = v.document_type
            else:
                pass

            if typename:
                fields[k] = typename, required, foreignkey, primarykey

        info = []
        update_info = []
        foreignkey_info = []

        update_by = False

        for k, v in fields.items():
            typename, required, foreignkey, primarykey = v
            update_typename = typename.replace("ChoiceModel", "int")

            if k in ("create_by", "create_time", "update_by", "update_time"):
                if not update_by:
                    if info:
                        info[-1][-1] = True

                    if update_info:
                        update_info[-1][-1] = True

                update_by = True
            else:
                if update_by:
                    if info:
                        info[-1][-1] = True

                    if update_info:
                        update_info[-1][-1] = True

                update_by = False

            info.append([k, typename, required, foreignkey, False])

            if not primarykey and not update_by:
                update_info.append([k, update_typename, required, foreignkey, False])

            if not primarykey and foreignkey:
                if foreignkey_info:
                    if not foreignkey_info[-1][1]:
                        foreignkey_info[-1][-1] = True
                    else:
                        if not required:
                            foreignkey_info[-1][-1] = True

                description = (foreignkey.__doc__ or "").strip().splitlines()[0]
                foreignkey_info.append([k, required, foreignkey, description, False])

        if info:
            info[-1][-1] = False

        if update_info:
            update_info[-1][-1] = False

        description = (document_obj.__doc__ or "").strip().splitlines()[0]
        prefix_description = " " * ((58 - len(description)) // 2) + description

        content = jinja2.Template(STRING).render(
            document=document_obj,
            info=info,
            update_info=update_info,
            foreignkey_info=foreignkey_info,
            description=description,
            prefix_description=prefix_description,
        )

        content = "\n".join([x[12:].rstrip() for x in content.splitlines()]).strip()

        click.echo(content)

    @click.command("init_app")
    @click.argument("name")
    @click.argument("document")
    @staticmethod
    def init_app(name: str, document: str) -> None:
        """
        初始化app
        """

        def init_app(dirname: Path) -> None:
            """
            初始化
            """

            dirname.joinpath("api").mkdir(parents=True, exist_ok=True)
            dirname.joinpath("schemas").mkdir(parents=True, exist_ok=True)

            STRING = """
                from fastapi import APIRouter

                from . import login
                from . import info
                from . import upload


                app = APIRouter()


                app.include_router(login.app, tags=["登录"])
                app.include_router(info.app, tags=["用户信息"])
                app.include_router(upload.app, tags=["上传文件"])
            """

            content = jinja2.Template(STRING).render()
            content = "\n".join([x[16:].rstrip() for x in content.splitlines()]).strip()

            with open(
                dirname.joinpath("api").joinpath("__init__.py").as_posix(), "w"
            ) as f:
                f.write(content + "\n")

            STRING = """
                from base.schemas import *

                from .info import *
            """

            content = jinja2.Template(STRING).render()
            content = "\n".join([x[16:].rstrip() for x in content.splitlines()]).strip()

            with open(
                dirname.joinpath("schemas").joinpath("__init__.py").as_posix(), "w"
            ) as f:
                f.write(content + "\n")

            STRING = '''
                from base.schemas import *
                from models import *


                # ----------------------------------------------------------
                #
                #                          用户信息
                #
                # ----------------------------------------------------------


                class UserInfoModel(BaseModel):
                    """
                    用户信息
                    """

                    id: str
                    username: str

                    def update(self, obj: Any) -> None:
                        """
                        更新数据
                        """


                class UserInfoUpdateModel(BaseModel):
                    """
                    用户更新信息
                    """

                    username: str

                    def update(self, obj: Any) -> None:
                        """
                        更新数据
                        """
            '''

            content = jinja2.Template(STRING).render()
            content = "\n".join([x[16:].rstrip() for x in content.splitlines()]).strip()

            with open(
                dirname.joinpath("schemas").joinpath("info.py").as_posix(), "w"
            ) as f:
                f.write(content + "\n")

            STRING = """
                from base.app import init_app, init_api

                from . import api


                {{ app }} = init_app()
                {{ app }}.include_router(api.app)

                init_api({{ app }})
            """

            content = jinja2.Template(STRING).render(app=dirname.name)
            content = "\n".join([x[16:].rstrip() for x in content.splitlines()]).strip()

            with open(dirname.joinpath("__init__.py").as_posix(), "w") as f:
                f.write(content + "\n")

            STRING = """
                {% for app in apps -%}
                from .{{ app }} import {{ app }}
                {% endfor %}
            """

            apps = []

            for x in dirname.joinpath("..").iterdir():
                if x.is_dir():
                    if x.name.startswith(".") or x.name.startswith("_"):
                        continue

                    apps.append(x.name)

            content = jinja2.Template(STRING).render(apps=sorted(apps))
            content = "\n".join([x[16:].rstrip() for x in content.splitlines()]).strip()

            with open(dirname.joinpath("..", "__init__.py").as_posix(), "w") as f:
                f.write(content + "\n")

        def init_app_info(dirname: Path, name: str, document_obj: Document) -> None:
            """
            用户信息
            """

            STRING = '''
                """
                用户信息
                """

                from fastapi import APIRouter, Request

                from base.app import limiter
                from base.auth import authentication
                from base.exception import *

                from app.{{ app }}.schemas import *


                app = APIRouter()


                class UserInfoAPI(Request):
                    @app.get(
                        "/info",
                        response_model=UserInfoModel,
                        summary="获取用户信息",
                    )
                    async def info(request: Request) -> UserInfoModel:
                        """
                        获取用户信息
                        """

                        auth_user = authentication(request.user, "{{ app }}")

                        response_model = UserInfoModel.from_obj(auth_user)
                        response_model.update(auth_user)

                        return response_model

                    @app.put(
                        "/update",
                        response_model=SuccessModel,
                        summary="更新用户信息",
                    )
                    async def update(request: Request, data: UserInfoUpdateModel) -> SuccessModel:
                        """
                        更新用户信息
                        """

                        auth_user = authentication(request.user, "{{ app }}")

                        auth_user.from_data(data.dict())
                        data.update(auth_user)

                        auth_user.validate_data()
                        auth_user.save()

                        return SuccessModel()
            '''

            if name in ("admin",):
                STRING += '''
                    @app.get(
                        "/menu",
                        response_model=ListModel,
                        summary="菜单列表",
                    )
                    async def menu(request: Request) -> ListModel:
                        """
                        菜单列表
                        """

                        auth_user = authentication(request.user, "{{ app }}")

                        response_model = ListModel()
                        response_model.update()

                        return response_model
                '''

            content = jinja2.Template(STRING).render(app=name, document=document_obj)
            content = "\n".join([x[16:].rstrip() for x in content.splitlines()]).strip()

            with open(dirname.joinpath("info.py").as_posix(), "w") as f:
                f.write(content + "\n")

        def init_app_login(dirname: Path, name: str, document_obj: Document) -> None:
            """
            登录
            """

            STRING = '''
                """
                登录
                """

                import hashlib

                from fastapi import APIRouter, Request

                from base.app import limiter
                from base.auth import authentication
                from base.exception import *
                from base.redis import Redis
                from base.util import decode_aes, make_token

                from app.{{ app }}.schemas import *


                app = APIRouter()


                class LoginAPI(Request):
                    @app.post(
                        "/login",
                        response_model=LoginSuccessModel,
                        summary="登录",
                    )
                    @limiter.limit("1 per 10 second")
                    async def login(
                        request: Request, data: PasswordLoginArgsModel
                    ) -> LoginSuccessModel:
                        """
                        登录
                        """

                        auth_user = {{ document.__name__ }}.objects(username=data.username).first()

                        if not auth_user:
                            raise HTTPException(
                                detail="账号未授权",
                                status_code=HTTP_400_BAD_REQUEST,
                            )

                        if not auth_user.enable:
                            raise HTTPException(
                                detail="账号未启用",
                                status_code=HTTP_400_BAD_REQUEST,
                            )

                        password = decode_aes(data.password)

                        if (not password) or auth_user.password != password:
                            raise HTTPException(
                                detail="密码错误",
                                status_code=HTTP_400_BAD_REQUEST,
                            )

                        token = make_token(str(auth_user.id), "{{ app }}")

                        with Redis() as conn:
                            conn.set(
                                hashlib.sha256(token.encode()).hexdigest(),
                                str(auth_user.id),
                                30 * 60,
                            )

                        return LoginSuccessModel(token=token)

                    @app.post(
                        "/logout",
                        response_model=SuccessModel,
                        summary="退出",
                    )
                    @limiter.limit("1 per 10 second")
                    async def logout(request: Request) -> SuccessModel:
                        """
                        退出
                        """

                        auth_user = authentication(request.user, "{{ app }}")

                        with Redis() as conn:
                            conn.delete(request.user.token_hexdigest())

                        return SuccessModel()
            '''

            content = jinja2.Template(STRING).render(app=name, document=document_obj)
            content = "\n".join([x[16:].rstrip() for x in content.splitlines()]).strip()

            with open(dirname.joinpath("login.py").as_posix(), "w") as f:
                f.write(content + "\n")

        def init_app_upload(dirname: Path, name: str) -> None:
            """
            上传文件
            """

            STRING = '''
                """
                上传文件
                """

                import puremagic

                from io import BytesIO

                from fastapi import APIRouter, Request, UploadFile
                from PIL import Image

                from base.app import limiter
                from base.auth import authentication
                from base.exception import *

                from app.{{ app }}.schemas import *


                app = APIRouter()


                class UploadAPI(Request):
                    @app.post(
                        "/upload",
                        response_model=FileModel,
                        summary="上传文件",
                    )
                    @limiter.limit("1 per 10 second")
                    async def upload(request: Request, file: UploadFile) -> FileModel:
                        """
                        上传文件
                        """

                        auth_user = authentication(request.user, "{{ app }}")

                        try:
                            content = await file.read()
                        except BaseException:
                            raise HTTPException(
                                detail="读取文件失败",
                                status_code=HTTP_400_BAD_REQUEST,
                            )

                        filename = request.query_params.get("filename")

                        if not filename:
                            filename = (
                                Path("upload")
                                .joinpath(
                                    localtime().format("YYYYMMDD"),
                                    Path(ulid.ulid()).with_suffix(Path(file.filename).suffix),
                                )
                                .as_posix()
                            )

                        try:
                            for x in puremagic.magic_string(content):
                                if x.mime_type.startswith("image/"):
                                    ios = BytesIO()

                                    image = Image.open(BytesIO(content))
                                    image.save(ios, "webp")

                                    ios.seek(0)
                                    content = ios.read()

                                    filename = Path(filename).with_suffix(".webp").as_posix()

                                    break
                        except Exception:
                            pass

                        storage = StorageField(filename)

                        if not storage.save(content):
                            raise HTTPException(
                                detail="上传文件失败",
                                status_code=HTTP_400_BAD_REQUEST,
                            )

                        return FileModel(path=storage.url)
            '''

            content = jinja2.Template(STRING).render(app=name)
            content = "\n".join([x[16:].rstrip() for x in content.splitlines()]).strip()

            with open(dirname.joinpath("upload.py").as_posix(), "w") as f:
                f.write(content + "\n")

        document_obj = Generate.get_document(document)

        if not document_obj:
            raise click.ClickException(f"未知文档: {document}")

        dirname = Path(BASE_DIR).joinpath("app", name)

        init_app(dirname)
        init_app_info(dirname.joinpath("api"), name, document_obj)
        init_app_login(dirname.joinpath("api"), name, document_obj)
        init_app_upload(dirname.joinpath("api"), name)

    @click.command("crud")
    @click.argument("app")
    @click.argument("document")
    @click.argument("deletes", required=False)
    @click.argument("queryset", required=False)
    @click.argument("permission", required=False)
    @staticmethod
    def crud(
        app: str,
        document: str = None,
        deletes: bool = False,
        queryset: bool = False,
        permission: bool = False,
    ) -> None:
        """
        生成crud
        """

        STRING = '''
            """
            {{ description }}
            """

            from fastapi import APIRouter, Request

            from base.app import limiter
            from base.auth import authentication
            from base.exception import *

            from app.{{ app }}.schemas import *


            app = APIRouter()


            class {{ document.__name__ }}API(Request):
                {% if queryset -%}
                @staticmethod
                def queryset(
                    queryset: mongoengine.QuerySet, data: dict, kwargs: str | None = None
                ) -> mongoengine.QuerySet:
                    """
                    设置查询条件
                    """

                    kwargs = str(kwargs or "").strip()

                    if kwargs:
                        pass

                    return queryset

                {% endif -%}
                @app.get(
                    "/{{ prefix }}",
                    response_model=PaginationModel,
                    summary="{{ description }}分页列表",
                )
                async def list(
                    request: Request, page: int = 1, limit: int = 10, kwargs: str | None = None
                ) -> PaginationModel:
                    """
                    {{ description }}分页列表
                    """

                    {% if permission -%}
                    auth_user = authentication(request.user, "{{ app }}", True)
                    {% else -%}
                    auth_user = authentication(request.user, "{{ app }}")
                    {% endif %}
                    input_model = PaginationArgsModel(page=page, limit=limit)
                    response_model = PaginationModel()

                    queryset = {{ document.__name__ }}.objects
                    {% if queryset -%}
                    queryset = {{ document.__name__ }}API.queryset(queryset, request.query_params, kwargs)
                    {% endif %}
                    response_model.init(queryset, input_model._limit())

                    for obj in input_model.queryset(queryset.order_by("-{{ primarykey }}")):
                        model = {{ document.__name__ }}PaginationModel.from_obj(obj)
                        model.update(obj)

                        response_model.data.append(model)

                    return response_model

                @app.get(
                    "/{{ prefix }}/{id:str}",
                    response_model={{ document.__name__ }}Model,
                    summary="获取{{ description }}信息",
                )
                async def get(request: Request, id: str) -> {{ document.__name__ }}Model:
                    """
                    获取{{ description }}信息
                    """

                    {% if permission -%}
                    auth_user = authentication(request.user, "{{ app }}", True)
                    {% else -%}
                    auth_user = authentication(request.user, "{{ app }}")
                    {% endif %}
                    obj = {{ document.__name__ }}.objects(id=id).first()

                    if not obj:
                        raise HTTPException(
                            detail="未知{{ description }}",
                            status_code=HTTP_400_BAD_REQUEST,
                        )

                    response_model = {{ document.__name__ }}Model.from_obj(obj)
                    response_model.update(obj)

                    return response_model

                @app.post(
                    "/{{ prefix }}",
                    response_model=SuccessModel,
                    summary="新建{{ description }}",
                )
                @limiter.limit("1 per 10 second")
                async def create_{{ document.__name__.lower() }}(
                    request: Request, data: {{ document.__name__ }}CreateModel
                ) -> SuccessModel:
                    """
                    新建{{ description }}
                    """

                    {% if permission -%}
                    auth_user = authentication(request.user, "{{ app }}", True)
                    {% else -%}
                    auth_user = authentication(request.user, "{{ app }}")
                    {% endif %}
                    {% if create_by -%}
                    obj = {{ document.__name__ }}(create_by=auth_user.name)
                    {% else -%}
                    obj = {{ document.__name__ }}()
                    {% endif %}
                    obj.from_data(data.dict())
                    data.update(obj)

                    obj.validate_data()
                    obj.save()

                    return SuccessModel()

                @app.put(
                    "/{{ prefix }}/{id:str}",
                    response_model=SuccessModel,
                    summary="更新{{ description }}",
                )
                async def update(
                    request: Request, id: str, data: {{ document.__name__ }}UpdateModel
                ) -> SuccessModel:
                    """
                    更新{{ description }}
                    """

                    {% if permission -%}
                    auth_user = authentication(request.user, "{{ app }}", True)
                    {% else -%}
                    auth_user = authentication(request.user, "{{ app }}")
                    {% endif %}
                    obj = {{ document.__name__ }}.objects(id=id).first()

                    if not obj:
                        raise HTTPException(
                            detail="未知{{ description }}",
                            status_code=HTTP_400_BAD_REQUEST,
                        )
                    {%- if update_by %}

                    obj.update_by = auth_user.name
                    obj.update_time = now()
                    {%- endif %}

                    obj.from_data(data.dict())
                    data.update(obj)

                    obj.validate_data()
                    obj.save()

                    return SuccessModel()

                {% if deletes -%}
                @app.delete(
                    "/{{ prefix }}",
                    response_model=SuccessModel,
                    summary="删除{{ description }}",
                )
                async def delete(request: Request, ids: List[str]) -> SuccessModel:
                    """
                    删除{{ description }}
                    """

                    {% if permission -%}
                    auth_user = authentication(request.user, "{{ app }}", True)
                    {% else -%}
                    auth_user = authentication(request.user, "{{ app }}")
                    {% endif %}
                    {{ document.__name__ }}.objects(id__in=ids).delete()

                    return SuccessModel()
                {% else -%}
                    @app.delete(
                    "/{{ prefix }}/{id:str}",
                    response_model=SuccessModel,
                    summary="删除{{ description }}",
                )
                async def delete(request: Request, id: str) -> SuccessModel:
                    """
                    删除{{ description }}
                    """

                    {% if permission -%}
                    auth_user = authentication(request.user, "{{ app }}", True)
                    {% else -%}
                    auth_user = authentication(request.user, "{{ app }}")
                    {% endif %}
                    {{ document.__name__ }}.objects(id=id).delete()

                    return SuccessModel()
                {%- endif %}
        '''

        document_obj = Generate.get_document(document)

        if not document_obj:
            raise click.ClickException(f"未知文档: {document}")

        if not (document_obj.__doc__ or "").strip().splitlines():
            raise Exception("未填写文档注释, 生成失败")

        description = (document_obj.__doc__ or "").strip().splitlines()[0]
        prefix = snake_case(document_obj.__name__)

        if app in ("admin",):
            permission = True

        primarykey = "id"

        for k, v in document_obj._fields.items():
            if v.primary_key:
                primarykey = k

                break

        update_by = hasattr(document_obj, "update_by")
        create_by = hasattr(document_obj, "create_by")

        content = jinja2.Template(STRING).render(
            app=app,
            document=document_obj,
            prefix=prefix,
            description=description,
            deletes=deletes,
            queryset=queryset,
            permission=permission,
            primarykey=primarykey,
            update_by=update_by,
            create_by=create_by,
        )

        content = "\n".join([x[12:].rstrip() for x in content.splitlines()]).strip()

        click.echo(content)

    @click.command("choice")
    @click.argument("app")
    @click.argument("document")
    @click.argument("permission", required=False)
    @staticmethod
    def choice(app: str, document: str, permission: bool = False) -> None:
        """
        生成choice
        """

        STRING = '''
            class {{ document.__name__ }}ChoiceAPI(Request):
                {% for choice in choices -%}
                @app.get(
                    "/{{ prefix }}/choice/{{ choice.name }}",
                    response_model=ListModel,
                    summary="{{ choice.verbose_name or "" }}列表",
                )
                async def choice_{{ choice.name }}(request: Request) -> ListModel:
                    """
                    {{ choice.verbose_name or "" }}列表
                    """

                    auth_user = authentication(request.user, "{{ app }}")

                    response_model = ListModel()

                    for choice in {{ document.__name__ }}.{{ choice.name  }}._choices:
                        model = ChoiceModel.from_obj(choice)
                        response_model.data.append(model)

                    response_model.update()

                    return response_model

                {% endfor -%}
        '''

        document_obj = Generate.get_document(document)

        if not document_obj:
            raise click.ClickException(f"未知文档: {document}")

        choices = []

        for k, v in document_obj._fields.items():
            if isinstance(v, ChoiceField):
                choices.append(v)

        if choices:
            prefix = snake_case(document_obj.__name__)

            if app in ("admin",):
                permission = True

            content = jinja2.Template(STRING).render(
                app=app,
                document=document_obj,
                choices=choices,
                prefix=prefix,
                permission=permission,
            )
            content = "\n".join([x[12:].rstrip() for x in content.splitlines()]).strip()

            click.echo(content)

    @click.command("foreignkey")
    @click.argument("app")
    @click.argument("document")
    @click.argument("permission", required=False)
    @staticmethod
    def foreignkey(app: str, document: str, permission: bool = False) -> None:
        """
        生成foreignkey
        """

        STRING = '''
            class {{ document.__name__ }}ForeignKeyAPI(Request):
                {% for foreignkey in foreignkeys -%}
                @app.get(
                    "/{{ prefix }}/foreignkey/{{ foreignkey.name }}",
                    response_model=ListModel,
                    summary="{{ foreignkey.verbose_name or "" }}列表",
                )
                async def foreignkey_{{ foreignkey.name }}(request: Request) -> ListModel:
                    """
                    {{ foreignkey.verbose_name or "" }}列表
                    """

                    auth_user = authentication(request.user, "{{ app }}")

                    response_model = ListModel()

                    queryset = {{ foreignkey.document_type.__name__ }}.objects

                    for obj in queryset.order_by("id"):
                        model = NameModel.from_obj(obj)
                        response_model.data.append(model)

                    response_model.update()

                    return response_model

                {% endfor -%}
        '''

        document_obj = Generate.get_document(document)

        if not document_obj:
            raise click.ClickException(f"未知文档: {document}")

        foreignkeys = []

        for k, v in document_obj._fields.items():
            if isinstance(
                v,
                ReferenceField
                | CachedReferenceField
                | GenericReferenceField
                | LazyReferenceField,
            ):
                foreignkeys.append(v)

        if foreignkeys:
            prefix = snake_case(document_obj.__name__)

            if app in ("admin",):
                permission = True

            content = jinja2.Template(STRING).render(
                app=app,
                document=document_obj,
                foreignkeys=foreignkeys,
                prefix=prefix,
                permission=permission,
            )
            content = "\n".join([x[12:].rstrip() for x in content.splitlines()]).strip()

            click.echo(content)

    @click.command("relationship")
    @click.argument("app")
    @click.argument("document")
    @click.argument("secondary_document")
    @click.argument("permission", required=False)
    @staticmethod
    def relationship(
        app: str, document: str, secondary_document: str, permission: bool = False
    ) -> None:
        """
        生成relationship
        """

        STRING = '''
            class {{ document.__name__ }}{{ secondary_document.__name__ }}API(Request):
                @app.get(
                    "/{{ prefix }}/{id:str}/relationship/{{ secondary_name }}/exists",
                    response_model=PaginationModel,
                    summary="已选{{ description }}关联{{ secondary_description }}分页列表",
                )
                async def exists(
                    request: Request, id: str, page: int = 1, limit: int = 10, kwargs: str = None
                ) -> PaginationModel:
                    """
                    已选{{ description }}关联{{ secondary_description }}分页列表
                    """

                    {% if permission -%}
                    auth_user = authentication(request.user, "{{ app }}", True)
                    {% else -%}
                    auth_user = authentication(request.user, "{{ app }}")
                    {% endif %}
                    input_model = PaginationArgsModel(page=page, limit=limit)
                    response_model = PaginationModel()

                    obj = {{ document.__name__ }}.objects(id=id).first()

                    if not obj:
                        raise HTTPException(
                            detail="未知{{ description }}",
                            status_code=HTTP_400_BAD_REQUEST,
                        )

                    sub_queryset = {{ document.__name__ }}{{ secondary_document.__name__ }}.objects({{ name }}=obj)
                    queryset = {{ secondary_document.__name__ }}.objects(
                        id__in=[x.id for x in sub_queryset.scalar("{{ secondary_name }}").no_dereference()]
                    )

                    kwargs = str(kwargs or "").strip()

                    if kwargs:
                        pass

                    response_model.init(queryset, input_model._limit())

                    for relationship_obj in input_model.queryset(queryset.order_by("-{{ secondary_name }}")):
                        model = {{ document.__name__ }}{{ secondary_document.__name__ }}PaginationModel.from_obj(relationship_obj)
                        model.update(relationship_obj)

                        response_model.data.append(model)

                    return response_model

                @app.get(
                    "/{{ prefix }}/{id:str}/relationship/{{ secondary_name }}/remaining",
                    response_model=PaginationModel,
                    summary="未选{{ description }}关联{{ secondary_description }}分页列表",
                )
                async def remaining(
                    request: Request, id: str, page: int = 1, limit: int = 10, kwargs: str = None
                ) -> PaginationModel:
                    """
                    未选{{ description }}关联{{ secondary_description }}分页列表
                    """

                    {% if permission -%}
                    auth_user = authentication(request.user, "{{ app }}", True)
                    {% else -%}
                    auth_user = authentication(request.user, "{{ app }}")
                    {% endif %}
                    input_model = PaginationArgsModel(page=page, limit=limit)
                    response_model = PaginationModel()

                    obj = {{ document.__name__ }}.objects(id=id).first()

                    if not obj:
                        raise HTTPException(
                            detail="未知{{ description }}",
                            status_code=HTTP_400_BAD_REQUEST,
                        )

                    sub_queryset = {{ document.__name__ }}{{ secondary_document.__name__ }}.objects({{ name }}=obj)
                    queryset = {{ secondary_document.__name__ }}.objects(
                        id__nin=[x.id for x in sub_queryset.scalar("{{ secondary_name }}").no_dereference()]
                    )

                    kwargs = str(kwargs or "").strip()

                    if kwargs:
                        pass

                    response_model.init(queryset, input_model._limit())

                    for relationship_obj in input_model.queryset(queryset.order_by("-{{ secondary_name }}")):
                        model = {{ document.__name__ }}{{ secondary_document.__name__ }}PaginationModel.from_obj(relationship_obj)
                        model.update(relationship_obj)

                        response_model.data.append(model)

                    return response_model

                @app.post(
                    "/{{ prefix }}/{id:str}/relationship/{{ secondary_name }}/add",
                    response_model=SuccessModel,
                    summary="新增{{ description }}关联{{ secondary_description }}",
                )
                async def add(request: Request, id: str, ids: List[str]) -> SuccessModel:
                    """
                    新增{{ description }}关联{{ secondary_description }}
                    """

                    {% if permission -%}
                    auth_user = authentication(request.user, "{{ app }}", True)
                    {% else -%}
                    auth_user = authentication(request.user, "{{ app }}")
                    {% endif %}
                    obj = {{ document.__name__ }}.objects(id=id).first()

                    if not obj:
                        raise HTTPException(
                            detail="未知{{ description }}",
                            status_code=HTTP_400_BAD_REQUEST,
                        )

                    queryset = {{ secondary_document.__name__ }}.objects(id__in=ids)

                    for secondary_obj in queryset.order_by("-id"):
                        relationship_obj = {{ document.__name__ }}{{ secondary_document.__name__ }}.objects(
                            {{ name }}=obj, {{ secondary_name }}=secondary_obj
                        ).first()

                        if not relationship_obj:
                            relationship_obj = {{ document.__name__ }}{{ secondary_document.__name__ }}({{ name }}=obj, {{ secondary_name }}=relationship_obj)
                            relationship_obj.save()

                    return SuccessModel()

                @app.delete(
                    "/{{ prefix }}/{id:str}/relationship/{{ secondary_name }}/delete",
                    response_model=SuccessModel,
                    summary="删除{{ description }}关联{{ secondary_description }}",
                )
                async def delete(request: Request, id: str, ids: List[str]) -> SuccessModel:
                    """
                    删除{{ description }}关联{{ secondary_description }}
                    """

                    {% if permission -%}
                    auth_user = authentication(request.user, "{{ app }}", True)
                    {% else -%}
                    auth_user = authentication(request.user, "{{ app }}")
                    {% endif %}
                    {{ document.__name__ }}{{ secondary_document.__name__ }}.objects({{ name }}=id, {{ secondary_name }}__in=ids).delete()

                    return SuccessModel()
        '''

        document_obj = Generate.get_document(document)

        if not document_obj:
            raise click.ClickException(f"未知文档: {document}")

        if not (document_obj.__doc__ or "").strip().splitlines():
            raise Exception("未填写文档注释, 生成失败")

        description = (document_obj.__doc__ or "").strip().splitlines()[0]

        secondary_document_obj = Generate.get_document(secondary_document)

        if not secondary_document_obj:
            raise click.ClickException(f"未知文档: {secondary_document}")

        if not (secondary_document_obj.__doc__ or "").strip().splitlines():
            raise Exception("未填写文档注释, 生成失败")

        secondary_description = (
            (secondary_document_obj.__doc__ or "").strip().splitlines()[0]
        )

        prefix = snake_case(document_obj.__name__)

        if app in ("admin",):
            permission = True

        content = jinja2.Template(STRING).render(
            app=app,
            name=snake_case(document_obj.__name__),
            document=document_obj,
            description=description,
            secondary_document=secondary_document_obj,
            secondary_description=secondary_description,
            secondary_name=snake_case(secondary_document_obj.__name__),
            prefix=prefix,
            permission=permission,
        )

        content = "\n".join([x[12:].rstrip() for x in content.splitlines()]).strip()

        click.echo(content)

    @click.group()
    @staticmethod
    def command():
        pass

    command.add_command(document)
    command.add_command(relationship_document)
    command.add_command(schema)
    command.add_command(init_app)
    command.add_command(crud)
    command.add_command(choice)
    command.add_command(foreignkey)
    command.add_command(relationship)


if __name__ == "__main__":
    Generate.command()
