from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from web import models
from ext.hook import HookSerializer
from web.models import CarmiInfo, CarmiBuyLog


class CarmiInfoSerializer(HookSerializer, serializers.ModelSerializer):
    """获取卡密时候的序列化操作"""

    # 自定义字段
    # generate_user = serializers.CharField(source="generate_useID.account")
    # using_user = serializers.CharField(source="generate_useID.account")
    # status = serializers.CharField(source="get_carmi_status_display")
    # generate_time = serializers.DateTimeField(source="generating_time", format="%Y-%m-%d %H:%M:%S", write_only=True)
    generate_nums = serializers.IntegerField(write_only=True)

    # 自定义数据
    # xxx = serializers.SerializerMethodField()
    # carmi_status = serializers.SerializerMethodField()

    class Meta:
        model = models.CarmiInfo
        # fields = "__all__"
        fields = [
            "id", "carmi_code", "carmi_duration", "carmi_buy_status", "carmi_use_status", "generate_nums",
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "carmi_code": {"read_only": True},
            "carmi_buy_status": {"read_only": True},
            "carmi_use_status": {"read_only": True},
        }

    # 验证器：确保 carmi_duration 大于 0
    def validate_carmi_duration(self, value):
        if value <= 0:
            raise serializers.ValidationError("carmi_duration 必须大于 0")
        return value

    # 自定义钩子
    def hook_carmi_buy_status(self, obj):
        return obj.get_carmi_buy_status_display()

    def hook_carmi_use_status(self, obj):
        return obj.get_carmi_use_status_display()

    # 自定义数据处理方法
    # def get_xxx(self, obj):
    #     return "name:
    # def get_status(self, obj):
    #     return obj.get_carmi_status_display()


"""
class CarmiInfoDetailSerializer(HookSerializer, serializers.ModelSerializer):
    # 自定义字段
    # status = serializers.CharField(source="get_carmi_status_display")

    # 自定义数据
    # status = serializers.SerializerMethodField()

    class Meta:
        model = models.CarmiInfo
        # fields = "__all__"
        fields = ["id", "carmi_code", "carmi_duration", "carmi_buy_status", "carmi_use_status"]
        extra_kwargs = {
            "id": {"read_only": True},
            "carmi_status": {"read_only": True},
        }

    # 自定义钩子
    def hook_carmi_buy_status(self, obj):
        return obj.get_carmi_buy_status_display()

    def hook_carmi_use_status(self, obj):
        return obj.get_carmi_use_status_display()

    # 自定义数据处理方法
    # def get_status(self, obj):
    #     return obj.get_carmi_status_display()
"""


class CarmiGenLogSerializer(HookSerializer, serializers.ModelSerializer):
    # 自定义字段
    # status = serializers.CharField(source="get_carmi_status_display")
    generating_time = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S")

    carmi_code_id = serializers.SerializerMethodField(source="carmi_code_id")
    generating_user_id = serializers.SerializerMethodField(source="generating_user_id")

    # 自定义数据
    # carmi = serializers.SerializerMethodField()

    class Meta:
        model = models.CarmiGenLog
        # fields = "__all__"
        fields = ["id", "carmi_code_id", "carmi_code", "generating_user_id", "generating_user", "generating_time"]

    # 自定义钩子
    def hook_carmi_code(self, obj):
        return obj.carmi_code.carmi_code

    def hook_generating_user(self, obj):
        return obj.generating_user.username

    def hook_carmi_code_id(self, obj):
        return obj.carmi_code_id

    def hook_generating_user_id(self, obj):
        return obj.generating_user_id

    # 自定义数据处理方法
    # def get_carmi(self, obj):
    #     return obj.carmi.carmi_code


class CarmiBuySerializer(HookSerializer, serializers.ModelSerializer):
    """购买卡密时候的序列化操作"""
    # 自定义字段
    # generate_user = serializers.CharField(source="generate_useID.account")
    # using_user = serializers.CharField(source="generate_useID.account")
    carmi_counts = serializers.IntegerField(write_only=True)
    carmi_buy_counts = serializers.IntegerField(write_only=True)

    # 自定义数据
    # xxx = serializers.SerializerMethodField()
    # carmi_status = serializers.SerializerMethodField()

    class Meta:
        model = models.CarmiInfo
        # fields = "__all__"
        fields = [
            "id", "carmi_code", "carmi_duration", "carmi_buy_status", "carmi_use_status", "carmi_counts",
            "carmi_buy_counts"
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "carmi_code": {"read_only": True},
        }

    def validate_carmi_counts(self, value):
        if value <= 0:
            print(value)
            raise serializers.ValidationError("此卡密已售罄!")
        return value

    def validate_carmi_buy_counts(self, value):
        if value <= 0:
            raise serializers.ValidationError("购买数量必须大于 0!")
        return value

    def validate(self, data):
        carmi_duration = data.get('carmi_duration')
        carmi_counts = data.get('carmi_counts')
        carmi_buy_counts = data.get('carmi_buy_counts')

        # 检查卡密时长是否存在
        if not CarmiInfo.objects.filter(carmi_duration=carmi_duration, carmi_buy_status=0).exists():
            raise serializers.ValidationError("指定时长的卡密不存在!")

        # 检查卡密货存是否足够
        if carmi_counts < carmi_buy_counts:
            raise serializers.ValidationError("指定卡密存货不足!")

        return data

    # def create(self, validated_data):
    #     carmi_duration = validated_data.get('carmi_duration')
    #     carmi_buy_counts = validated_data.get('carmi_buy_counts')
    #
    #     # 获取购买的卡密
    #     carmis_to_buy = CarmiInfo.objects.filter(carmi_duration=carmi_duration, carmi_buy_status=0)[:carmi_buy_counts]
    #
    #     # 更新购买状态和购买日志
    #     for carmi in carmis_to_buy:
    #         carmi.carmi_buy_status = 1
    #         carmi.save()
    #         # 创建购买记录
    #         # CarmiBuyLog.objects.create(carmi_code=carmi, buying_time=datetime.datetime.now())
    #
    #     return carmis_to_buy

    # 自定义钩子
    def hook_carmi_buy_status(self, obj):
        return obj.get_carmi_buy_status_display()

    def hook_carmi_use_status(self, obj):
        return obj.get_carmi_use_status_display()

    # 自定义数据处理方法
    # def get_xxx(self, obj):
    #     return "name:
    # def get_status(self, obj):
    #     return obj.get_carmi_status_display()


class CarmiBuyDetailSerializer(HookSerializer, serializers.ModelSerializer):
    """购买卡密时候的序列化操作"""

    # 自定义字段
    # generate_user = serializers.CharField(source="generate_useID.account")
    # using_user = serializers.CharField(source="generate_useID.account")

    # 自定义数据
    # xxx = serializers.SerializerMethodField()
    # carmi_status = serializers.SerializerMethodField()

    class Meta:
        model = models.CarmiInfo
        # fields = "__all__"
        fields = [
            "id", "carmi_code", "carmi_duration", "carmi_buy_status", "carmi_use_status",
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "carmi_code": {"read_only": True},
        }

    # 自定义钩子
    def hook_carmi_buy_status(self, obj):
        return obj.get_carmi_buy_status_display()

    def hook_carmi_use_status(self, obj):
        return obj.get_carmi_use_status_display()

    # 自定义数据处理方法
    # def get_xxx(self, obj):
    #     return "name:
    # def get_status(self, obj):
    #     return obj.get_carmi_status_display()


class CarmiBuyLogSerializer(HookSerializer, serializers.ModelSerializer):
    # 自定义字段
    # status = serializers.CharField(source="get_carmi_status_display")
    buying_time = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S")

    carmi_code_id = serializers.SerializerMethodField(source="carmi_code_id")
    buying_user_id = serializers.SerializerMethodField(source="buying_user_id")
    carmi_duration = serializers.SerializerMethodField(source="carmi_duration")
    carmi_buy_status = serializers.SerializerMethodField(source="carmi_buy_status")
    carmi_use_status = serializers.SerializerMethodField(source="carmi_use_status")

    # 自定义数据
    # carmi = serializers.SerializerMethodField()

    class Meta:
        model = models.CarmiBuyLog
        # fields = "__all__"
        fields = ["id", "carmi_code_id", "carmi_code", "buying_user_id", "buying_user", "buying_time","carmi_duration","carmi_buy_status","carmi_use_status"]

    # 自定义钩子
    def hook_carmi_code(self, obj):
        return obj.carmi_code.carmi_code

    def hook_buying_user(self, obj):
        return obj.buying_user.username

    def hook_carmi_code_id(self, obj):
        return obj.carmi_code_id

    def hook_buying_user_id(self, obj):
        return obj.buying_user_id

    def hook_carmi_duration(self, obj):
        return obj.carmi_code.carmi_duration
    def hook_carmi_buy_status(self, obj):
        return obj.carmi_code.get_carmi_buy_status_display()
    def hook_carmi_use_status(self, obj):
        return obj.carmi_code.get_carmi_use_status_display()



    # 自定义数据处理方法
    # def get_carmi(self, obj):
    #     return obj.carmi.carmi_code


class RegisterSerializer(serializers.ModelSerializer):
    # 自定义字段
    # status = serializers.CharField(source="get_carmi_status_display")
    # generating_time = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S")
    # using_time = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S")
    # 调用ser.data时候再次执行序列化操作，需要标记一些字段只是传入有但是不需要写入数据库的用write_only，
    # 相反序列化数据库有的但是不想序列化它，而它却在输入时候需要写入数据库的，则用read_only。
    confirm_password = serializers.CharField(write_only=True)

    # 自定义数据
    # carmi = serializers.SerializerMethodField()

    class Meta:
        model = models.UserInfo
        # fields = "__all__"
        fields = ["id", "username", "password", "confirm_password"]
        extra_kwargs = {
            "id": {"read_only": True},
            "password": {"write_only": True},
        }

    def validate_username(self, value):
        if models.UserInfo.objects.filter(username=value).exists():
            raise serializers.ValidationError("用户名已存在！")
        return value

    # 校验密码一致性
    def validate_confirm_password(self, value):
        password = self.initial_data.get("password")
        if password != value:
            raise ValidationError("密码不一致！")
        return value

    # 自定义数据处理方法
    # def get_carmi(self, obj):
    #     return obj.carmi.carmi_code


class LoginSerializer(HookSerializer,serializers.ModelSerializer):
    # 自定义字段
    # status = serializers.CharField(source="get_carmi_status_display")
    # generating_time = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S")
    # using_time = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S")
    # 调用ser.data时候再次执行序列化操作，需要标记一些字段只是传入有但是不需要写入数据库的用write_only，
    # 相反序列化数据库有的但是不想序列化它，而它却在输入时候需要写入数据库的，则用read_only。
    # confirm_password = serializers.CharField(write_only=True)

    # 自定义数据
    # carmi = serializers.SerializerMethodField()

    class Meta:
        model = models.UserInfo
        # fields = "__all__"
        fields = ["username", "password", "role"]
        extra_kwargs = {
            "role": {"read_only": True},
        }

    # def validate_username(self, value):
    #     if models.UserInfo.objects.filter(username=value).exists():
    #         raise serializers.ValidationError("用户名已存在！")
    #     return value
    #
    # # 校验密码一致性
    # def validate_confirm_password(self, value):
    #     password = self.initial_data.get("password")
    #     if password != value:
    #         raise ValidationError("密码不一致！")
    #     return value

    # 自定义数据处理方法
    # def get_carmi(self, obj):
    #     return obj.carmi.carmi_code
    def hook_role(self, obj):
        return obj.get_role_display()



class UserInfoSerializer(HookSerializer, serializers.ModelSerializer):
    """获取用户时候的序列化操作"""

    # 自定义字段
    # generate_user = serializers.CharField(source="generate_useID.account")

    # 自定义数据
    # xxx = serializers.SerializerMethodField()
    # carmi_status = serializers.SerializerMethodField()

    class Meta:
        model = models.UserInfo
        # fields = "__all__"
        fields = [
            "id", "username", "password", "role"
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            # "carmi_code": {"read_only": True},
        }

    # 验证器：确保 carmi_duration 大于 0
    # def validate_carmi_duration(self, value):
    #     if value <= 0:
    #         raise serializers.ValidationError("carmi_duration 必须大于 0")
    #     return value

    # 自定义钩子
    # def hook_carmi_buy_status(self, obj):
    #     return obj.get_carmi_buy_status_display()

    def hook_role(self, obj):
        return obj.get_role_display()

    # 自定义数据处理方法
    # def get_xxx(self, obj):
    #     return "name:
    # def get_status(self, obj):
    #     return obj.get_carmi_status_display()
