import re


def validate_business_license(code: str | None) -> bool:
    """
    校验统一社会信用代码

    统一社会信用代码编码规则
        第1位表示登记管理部门代码（1位字符）
            机构编制 1
            民政 5
            工商 9
            其他 Y

        第2位表示纳税人类别代码（1位字符）
            机构编制机关 1
            机构编制事业单位 2
            机构编制中央编办直接管理机构编制的群众团体 3
            机构编制其他 9

            民政社会团体 1
            民政民办非企业单位 2
            民政基金会 3
            民政其他 9

            工商企业 1
            工商个体工商户 2
            工商农民专业合作社 3

            其他 1

        第3 - 8位表示登记管理机关行政区划码(6位数字)
        第9 - 17位表示主体标识码(组织机构代码, 9位字符)
        第18位表示校验码（1位字符）
    """

    def validate_organization_code(code: str) -> bool:
        """
        校验组织机构代码校验码
        """

        ORGANIZATION_CHECK_CODE_DICT = {
            "0": 0,
            "1": 1,
            "2": 2,
            "3": 3,
            "4": 4,
            "5": 5,
            "6": 6,
            "7": 7,
            "8": 8,
            "9": 9,
            "A": 10,
            "B": 11,
            "C": 12,
            "D": 13,
            "E": 14,
            "F": 15,
            "G": 16,
            "H": 17,
            "I": 18,
            "J": 19,
            "K": 20,
            "L": 21,
            "M": 22,
            "N": 23,
            "O": 24,
            "P": 25,
            "Q": 26,
            "R": 27,
            "S": 28,
            "T": 29,
            "U": 30,
            "V": 31,
            "W": 32,
            "X": 33,
            "Y": 34,
            "Z": 35,
        }
        STRING = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

        factors = (3, 7, 9, 10, 5, 8, 4, 2)
        organization_code = code[8:17]

        check_code = gen_check_code(
            organization_code[:8], factors, 11, ORGANIZATION_CHECK_CODE_DICT
        )

        if check_code is None:
            return False

        if check_code == 11:
            check_code = 0
        elif check_code == 10:
            check_code = 33
        else:
            pass

        return STRING[check_code] == organization_code[8]

    def validate_unified_social_credit_code(code: str) -> bool:
        """
        校验统一社会信用代码校验码
        """

        # 统一社会信用代码中不使用I, O, S, V, Z
        SOCIAL_CREDIT_CHECK_CODE_DICT = {
            "0": 0,
            "1": 1,
            "2": 2,
            "3": 3,
            "4": 4,
            "5": 5,
            "6": 6,
            "7": 7,
            "8": 8,
            "9": 9,
            "A": 10,
            "B": 11,
            "C": 12,
            "D": 13,
            "E": 14,
            "F": 15,
            "G": 16,
            "H": 17,
            "J": 18,
            "K": 19,
            "L": 20,
            "M": 21,
            "N": 22,
            "P": 23,
            "Q": 24,
            "R": 25,
            "T": 26,
            "U": 27,
            "W": 28,
            "X": 29,
            "Y": 30,
        }
        STRING = "0123456789ABCDEFGHJKLMNPQRTUWXY"

        factors = (1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28)

        check_code = gen_check_code(
            code[:17], factors, 31, SOCIAL_CREDIT_CHECK_CODE_DICT
        )

        if check_code is None:
            return False

        if check_code == 31:
            check_code = 0

        return STRING[check_code] == code[17]

    def gen_check_code(
        code: str, factors: tuple[int] | list[int], mod: int, check_code_dict: dict
    ) -> int:
        """
        获取校验码
        """

        try:
            value = 0

            for i in range(len(code)):
                if code[i].isdigit():
                    value += int(code[i]) * factors[i]
                else:
                    value += check_code_dict.get(code[i]) * factors[i]

            return mod - value % mod
        except BaseException:
            return None

    if not isinstance(code, str):
        return False

    code = code.upper()

    if len(code) == 15:
        return True

    if not re.search(r"^(11|12|13|19|51|52|53|59|91|92|93|Y1)\d{6}\w{9}\w$", code):
        return False

    if not validate_organization_code(code):
        return False

    if not validate_unified_social_credit_code(code):
        return False

    return True


def validate_idcard(code: str | None) -> bool:
    """
    校验身份证号码

    中国居民身份证号码编码规则
        第1 - 2位表示省（直辖市、自治区、特别行政区）
            4个直辖市
                北京 11
                天津 12
                上海 31
                重庆 50

            5个自治区
                内蒙古 15
                广西 45
                西藏 54
                宁夏 64
                新疆 65

            2个特别行政区
                香港特别行政区 810000
                澳门特别行政区 820000

            23个省
                河北省 13
                山西省 14
                辽宁省 21
                吉林省 22
                黑龙江省 23
                江苏省 32
                浙江省 33
                安徽省 34
                福建省 35
                江西省 36
                山东省 37
                河南省 41
                湖北省 42
                湖南省 43
                广东省 44
                海南省 46
                四川省 51
                贵州省 52
                云南省 53
                陕西省 61
                甘肃省 62
                青海省 63
                台湾省 710000

        第3 - 4位表示市（地级市、自治州、盟及国家直辖市所属市辖区和县）
        第5 - 6位表示县（市辖区、县级市、旗）
        第7 - 14位表示出生年月日
        第15 - 17位表示顺序码（奇数为男性, 偶数为女性）
        第18位表示校验码（校验码如果出现数字10, 就用X来代替）
    """

    if not isinstance(code, str):
        return False

    code = code.upper()

    if not re.search(r"^[1-9][0-9]{14}([0-9]{2}[0-9X])$", code):
        return False

    # 加权系数
    factors = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)

    # 校验码
    check_codes = ("1", "0", "X", "9", "8", "7", "6", "5", "4", "3", "2")

    items = [int(item) for item in code[:-1]]
    value = sum([a * b for a, b in zip(factors, items)])

    return check_codes[value % 11] == code[-1]


def validate_password_secure(password: str) -> bool:
    """
    校验密码是否符合密码复杂度要求
    """

    from passwordlib.analyzer import Analyzer

    if not isinstance(password, str):
        return False

    analyzer = Analyzer(password)

    if analyzer.length < 8:
        return False

    if (
        analyzer.contains_lowercase
        + analyzer.contains_uppercase
        + analyzer.contains_digits
        + analyzer.contains_symbols
    ) < 3:
        return False

    return True


def validate_phone(phone: str | None) -> bool:
    """
    校验手机号码
    """

    if not isinstance(phone, str):
        return False

    if not re.search(r"^1[0-9]{10}$", phone):
        return False

    return True
