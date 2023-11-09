import datetime
import hmac
import zoneinfo

import arrow

from io import BytesIO
from jose import jwt


def now() -> datetime.datetime:
    """
    当前时间
    """

    import config

    return datetime.datetime.now(config.TIMEZONE)


def localtime(
    time: str
    | int
    | float
    | datetime.datetime
    | datetime.date
    | arrow.Arrow
    | None = None,
) -> arrow.Arrow:
    """
    本地时间
    """

    import config

    tzinfo = config.TIMEZONE

    if not time:
        time = now()

    if isinstance(time, str):
        time = arrow.parser.DateTimeParser().parse_iso(time, normalize_whitespace=True)

    if isinstance(time, datetime.datetime | arrow.Arrow):
        if time.tzinfo:
            tzinfo = time.tzinfo

    return arrow.get(time, tzinfo=tzinfo).to(config.TIMEZONE)


def encode_aes(text: str) -> str:
    """
    编码aes文本
    """

    import binascii
    import config

    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad

    cipher = AES.new(config.AES_KEY.encode(), AES.MODE_CBC, config.AES_IV.encode())

    try:
        encrypted_text = binascii.b2a_hex(
            cipher.encrypt(pad(text.encode(), 16, "pkcs7"))
        ).decode()
    except Exception:
        encrypted_text = None

    return encrypted_text


def decode_aes(text: str) -> str:
    """
    解码aes文本
    """

    import binascii
    import config

    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad

    cipher = AES.new(config.AES_KEY.encode(), AES.MODE_CBC, config.AES_IV.encode())

    try:
        decrypted_text = unpad(
            cipher.decrypt(binascii.a2b_hex(text)), 16, "pkcs7"
        ).decode()
    except Exception:
        decrypted_text = None

    return decrypted_text


def make_token(
    id: int | str, scope: str, data: dict | None = None, exp: bool = True
) -> str:
    """
    生成TOKEN
    """

    import config

    _data = {
        "id": str(id),
        "scope": scope,
        "data": data,
    }

    if exp:
        if data and data.get("exp"):
            _data["exp"] = localtime(data.get("exp")).datetime
        else:
            _data["exp"] = localtime().replace(hour=4).shift(days=1).datetime

    token = jwt.encode(_data, config.SECRET_KEY, algorithm="HS256")

    return token


def decode_token(token: str) -> (str, str, dict):
    """
    解析TOKEN
    """

    import config

    from base.exception import (
        HTTPException,
        HTTP_401_UNAUTHORIZED,
        HTTP_461_TOKEN_EXPIRED,
    )

    try:
        data = jwt.decode(token, config.SECRET_KEY, algorithms="HS256")
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            detail="认证过期",
            status_code=HTTP_461_TOKEN_EXPIRED,
        )
    except BaseException:
        raise HTTPException(
            detail="认证错误",
            status_code=HTTP_401_UNAUTHORIZED,
        )

    id = data.get("id")
    scope = data.get("scope")

    if not all((id, scope)):
        raise HTTPException(
            detail="认证错误",
            status_code=HTTP_401_UNAUTHORIZED,
        )

    return id, scope, data


def pdf2webp(content: bytes) -> bytes:
    """
    PDF转WEBP
    """

    import fitz

    from PIL import Image

    data = b""

    images = []

    try:
        document = fitz.open(stream=content)

        for page in document:
            trans = fitz.Matrix(2, 2).prerotate(0)

            images.append(
                Image.open(
                    BytesIO(page.get_pixmap(matrix=trans, alpha=False).tobytes())
                )
            )
    except Exception:
        pass

    if images:
        width = 0
        height = 0

        for image in images:
            width = max(width, image.width)
            height += image.height + 10

        target = Image.new("RGBA", (width, height - 10))

        cur_height = 0

        for image in images:
            target.paste(image, (0, cur_height))
            cur_height += image.height + 10

        ios = BytesIO()
        target.save(ios, "webp")
        ios.seek(0)

        data = ios.read()

    return data


def make_url(path: str, **query: dict) -> str:
    """
    构建URL
    """

    return "?".join(
        (path, "&".join(["{}={}".format(k, query[k]) for k in sorted(query)]))
    )


def sha256_hmac(content: bytes | str, secret_key: str | None = None) -> str:
    """
    SHA256 HMAC
    """

    import config

    m = hmac.new((secret_key or config.SECRET_KEY).encode(), digestmod="sha256")

    if isinstance(content, bytes):
        m.update(content)
    else:
        m.update(content.encode())

    return m.hexdigest()


def snake_case(name: str) -> str:
    """
    蛇形命名
    """

    chars = []

    upper = False

    for char in name:
        if "A" <= char <= "Z":
            if not upper:
                char = "_" + char
                upper = True
        else:
            if upper and chars:
                if not chars[-1].startswith("_"):
                    chars[-1] = "_" + chars[-1]

            upper = False

        chars.append(char.lower())

    return "".join(chars).strip("_")
