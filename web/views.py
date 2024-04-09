import datetime
import uuid
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.exceptions import Throttled, ValidationError, ParseError
from rest_framework.parsers import JSONParser, FormParser, FileUploadParser
from rest_framework.negotiation import DefaultContentNegotiation
from rest_framework import serializers
from .models import CarmiInfo, CarmiGenLog, UserInfo

from web import models
from ext import code
from ext.per import UserPermission, VipPermission, ManagerPermission
from ext.view import MyAPIView, ORPerAPIView
from ext.throttle import IpThrottle, UserThrottle, VipThrottle
from ext.hook import HookSerializer

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
            "id", "carmi_code", "carmi_duration", "carmi_status", "generate_nums",
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "carmi_code": {"read_only": True},
        }

    # 验证器：确保 carmi_duration 大于 0
    def validate_carmi_duration(self, value):
        if value <= 0:
            raise serializers.ValidationError("carmi_duration 必须大于 0")
        return value

    # 自定义钩子
    def hook_carmi_status(self, obj):
        return obj.get_carmi_status_display()

    # 自定义数据处理方法
    # def get_xxx(self, obj):
    #     return "name:
    # def get_status(self, obj):
    #     return obj.get_carmi_status_display()


class CarmiInfoView(ORPerAPIView):
    """所有卡密信息操作"""
    permission_classes = [VipPermission, ManagerPermission]  # 管理员和会员
    throttle_classes = [VipThrottle]

    # 卡密信息的获取
    def get(self, request, *args, **kwargs):
        # 获取数据库中数据
        queryset = models.CarmiInfo.objects.all().order_by("carmi_status")
        # 序列化
        ser = CarmiInfoSerializer(instance=queryset, many=True)
        context = {"code": code.SUCCESSFUL_CODE, "data": ser.data}
        return Response(context)

    # 传入生成个数和天数
    def post(self, request, *args, **kwargs):
        # 更新创建时间
        # models.CarmiInfo.objects.all().update(creat_time=datetime.datetime.now(), end_time=None)
        ser = CarmiInfoSerializer(data=request.data, many=False)
        if ser.is_valid():
            # 获取验证通过的数据
            validated_data = ser.validated_data

            # 从 validated_data 中获取生成卡密的数量和每个卡密的天数
            generate_nums = validated_data['generate_nums']
            carmi_duration = validated_data['carmi_duration']

            # 批量生成卡密并保存到数据库
            generated_carmis = []
            for _ in range(generate_nums):
                new_carmi = CarmiInfo.objects.create(
                    carmi_code=str(uuid.uuid4()).replace('-', ''),  # 生成唯一的卡密代码
                    carmi_duration=carmi_duration,
                    carmi_status=0  # 设置初始状态为未使用
                )
                generated_carmis.append(new_carmi)

            # 获取当前用户实例（假设根据用户名获取用户实例）
            generating_user = UserInfo.objects.get(username=request.user.username)

            # 批量创建生成记录并保存到数据库
            gen_logs = [CarmiGenLog(
                carmi_code=carmi,
                generating_user=generating_user,
                generating_time=datetime.datetime.now()  # 使用当前时间作为生成时间
            ) for carmi in generated_carmis]
            CarmiGenLog.objects.bulk_create(gen_logs)

            # 序列化生成的卡密信息
            serialized_data = CarmiInfoSerializer(generated_carmis, many=True).data

            return Response({"code": code.SUCCESSFUL_CODE, "data": serialized_data})
        else:
            return Response({"code": code.CARMIGEN_CODE, "error": "卡密生成失败！", "detail": ser.errors})


class CarmiInfoDetailSerializer(HookSerializer, serializers.ModelSerializer):
    # 自定义字段
    # status = serializers.CharField(source="get_carmi_status_display")

    # 自定义数据
    # status = serializers.SerializerMethodField()

    class Meta:
        model = models.CarmiInfo
        # fields = "__all__"
        fields = ["id", "carmi_code", "carmi_duration", "carmi_status"]
        extra_kwargs = {
            "id": {"read_only": True},
            "carmi_status": {"read_only": True},
        }

    # 自定义钩子
    def hook_carmi_status(self, obj):
        return obj.get_carmi_status_display()

    # 自定义数据处理方法
    # def get_status(self, obj):
    #     return obj.get_carmi_status_display()


class CarmiInfoDetailView(ORPerAPIView):
    """单卡密信息操作"""
    permission_classes = [ManagerPermission, VipPermission]  # 管理员和会员
    throttle_classes = [VipThrottle]  # 不限流

    def get(self, request, *args, **kwargs):
        # 获取卡密信息
        carmi_code = kwargs.get("carmi_code")
        # 获取数据库中数据
        instance = models.CarmiInfo.objects.filter(carmi_code=carmi_code).first()
        if not instance:
            return Response({"code": code.NODATA_CODE, "error": "卡密不存在！"})
        # 序列化
        ser = CarmiInfoDetailSerializer(instance=instance, many=False)
        context = {"code": code.SUCCESSFUL_CODE, "data": ser.data}
        return Response(context)

    def delete(self, request, *args, **kwargs):
        # 获取卡密信息
        carmi_code = kwargs.get("carmi_code")
        # 获取数据库中数据
        instance = models.CarmiInfo.objects.filter(carmi_code=carmi_code).first()
        if not instance:
            return Response({"code": code.NODATA_CODE, "error": "卡密不存在！"})
        # 序列化
        ser = CarmiInfoDetailSerializer(instance=instance, many=False)
        deleted_data = ser.data
        # 删除找到的卡密信息
        instance.delete()
        context = {"code": code.SUCCESSFUL_CODE, "data": deleted_data}
        return Response(context)


# class CarmiLogSerializer(HookSerializer, serializers.ModelSerializer):
#     # 自定义字段
#     # status = serializers.CharField(source="get_carmi_status_display")
#     generating_time = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S")
#     using_time = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S")
#
#     # 自定义数据
#     # carmi = serializers.SerializerMethodField()
#
#     class Meta:
#         model = models.CarmiLog
#         # fields = "__all__"
#         fields = ["id", "carmi_id", "carmi", "generating_user", "generating_time", "using_user", "using_machine",
#                   "using_time"]
#
#     # 自定义钩子
#     def hook_carmi(self, obj):
#         return obj.carmi.carmi_code
#
#     # 自定义数据处理方法
#     # def get_carmi(self, obj):
#     #     return obj.carmi.carmi_code
#
#
# class CarmiLogView(MyAPIView):
#     """所有卡密日志信息操作"""
#     authentication_classes = []  # 不需要token认证
#     permission_classes = []  # 无权限限制
#     throttle_classes = []  # 不限流
#
#     def get(self, request, *args, **kwargs):
#         # 更新创建时间
#         # models.CarmiInfo.objects.all().update(creat_time=datetime.datetime.now(), end_time=None)
#         # 获取数据库中数据，并且按照generating_time的时间降序排列，并且using_time为空的放在最上面
#         queryset = models.CarmiLog.objects.all()
#         print(queryset)
#         # 序列化
#         ser = CarmiLogSerializer(instance=queryset, many=True)
#         context = {"code": code.SUCCESSFUL_CODE, "data": ser.data}
#         return Response(context)
#
#     # def post(self, request, *args, **kwargs):
#     #     # 更新CarmiLog信息
#     #     ser = CarmiLogUpgradeSerializer(data=request.data, many=True)
#     #     if ser.is_valid():
#     #         ser.save()
#     #         return Response({"code": code.SUCCESSFUL_CODE, "data": ser.data})
#     #     else:
#     #         return Response({"code": code.CARMIGEN_CODE, "error": "卡密生成失败！", "detail": ser.errors})
#
#
# class CarmiLogDetailSerializer(HookSerializer, serializers.ModelSerializer):
#     # 自定义字段
#     # status = serializers.CharField(source="get_carmi_status_display")
#     generating_time = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S")
#     using_time = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S")
#
#     # 自定义数据
#     # carmi = serializers.SerializerMethodField()
#
#     class Meta:
#         model = models.CarmiLog
#         # fields = "__all__"
#         fields = ["id", "carmi_id", "carmi", "generating_user", "generating_time", "using_user", "using_machine",
#                   "using_time"]
#
#     # 自定义钩子
#     def hook_carmi(self, obj):
#         return obj.carmi.carmi_code
#
#     # 自定义数据处理方法
#     # def get_carmi(self, obj):
#     #     return obj.carmi.carmi_code
#
#
# class CarmiLogDetailView(MyAPIView):
#     """单个卡密日志信息操作"""
#     authentication_classes = []  # 不需要token认证
#     permission_classes = []  # 无权限限制
#     throttle_classes = []  # 不限流
#
#     def get(self, request, *args, **kwargs):
#         # 更新创建时间
#         # models.CarmiInfo.objects.all().update(creat_time=datetime.datetime.now(), end_time=None)
#         # 获取数据库中数据，并且按照generating_time的时间降序排列，并且using_time为空的放在最上面
#         # 获取卡密信息
#         carmi_code = kwargs.get("carmi_code")
#         carmiinfo_obj = models.CarmiInfo.objects.filter(carmi_code=carmi_code).first()
#         # 获取数据库中数据
#         instance = models.CarmiLog.objects.filter(carmi_id=carmiinfo_obj.id).first()
#         if not instance:
#             return Response({"code": code.NODATA_CODE, "error": "卡密日志不存在！"})
#         # 序列化
#         ser = CarmiLogDetailSerializer(instance=instance, many=False)
#         context = {"code": code.SUCCESSFUL_CODE, "data": ser.data}
#         return Response(context)
#
#     def post(self, request):
#         return Response("post")


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


class RegisterView(MyAPIView):
    """用户注册"""
    authentication_classes = []  # 不需要token认证
    permission_classes = []  # 无权限限制
    throttle_classes = [IpThrottle, ]  # 不限流

    def post(self, request, *args, **kwargs):
        # 数据校验
        ser = RegisterSerializer(data=request.data)
        if ser.is_valid():
            # 移除数据库没有的字段
            ser.validated_data.pop("confirm_password")
            ser.save()
            return Response({"code": code.SUCCESSFUL_CODE, "data": ser.data})
        else:
            return Response({"code": code.REGISTER_CODE, "error": "注册失败！", "detail": ser.errors})


class LoginSerializer(serializers.ModelSerializer):
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
        fields = ["username", "password"]

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


class LoginView(MyAPIView):
    """登录"""
    authentication_classes = []  # 不需要token认证
    permission_classes = []  # 无权限限制
    throttle_classes = [IpThrottle, ]  # 限流器

    def post(self, request, *args, **kwargs):
        # 数据校验
        ser = LoginSerializer(data=request.data)
        if not ser.is_valid():
            return Response({"code": code.VERIFY_CODE, "error": "登录校验失败！", "detail": ser.errors})
        instance = models.UserInfo.objects.filter(**ser.validated_data).first()
        if not instance:
            return Response({"code": code.Login_CODE, "error": "账号或密码错误！"})

        token = str(uuid.uuid4())
        instance.token = token
        instance.save()

        return Response({"code": code.SUCCESSFUL_CODE, "token": token})


class UserCarmiView(MyAPIView):
    """用户购买和使用卡密"""

    def get(self, resquest):
        pass

    def post(self, request):
        pass


class HomeView(MyAPIView):
    authentication_classes = []  # 不需要token认证
    permission_classes = []  # 无权限限制
    throttle_classes = []  # 限流

    # 解析器
    # parser_classes = [JSONParser,]
    # 根据请求，匹配对应的解析器；寻找渲染器
    # content_negotiation_class = DefaultContentNegotiation

    def get(self, request, *args, **kwargs):
        print(request.version)
        print(request.versioning_scheme)
        # 域名生成
        url = request.versioning_scheme.reverse("home", request=request)
        print(url)
        return Response("123123")

    def post(self, request, *args, **kwargs):
        print(request.data, type(request.data))
        return Response("OK")


class UserView(ORPerAPIView):
    # 管理员、会员、用户
    permission_classes = [UserPermission, VipPermission, ManagerPermission, ]
    throttle_classes = [UserThrottle, ]

    def get(self, request):
        print("user", request.user, request.auth)
        return Response("UserView")

    def post(self, request):
        print(request.user, request.auth)
        return Response("Post--UserView")


class OrderView(ORPerAPIView):
    # 管理员、会员
    # 权限列表
    permission_classes = [VipPermission, ManagerPermission, ]
    throttle_classes = [VipThrottle, ]

    def get(self, request):
        print(request.user, request.auth)
        return Response({"code": code.SUCCESSFUL_CODE, "data": [11, 22, 33, 44]})

    def post(self, request):
        print(request.user, request.auth)
        return Response({"code": code.SUCCESSFUL_CODE, "data": [11, 22, 33, 44]})


class AvatarView(ORPerAPIView):
    # 管理员
    permission_classes = [ManagerPermission, ]

    def get(self, request):
        print(request.user, request.auth)
        return Response({"code": code.SUCCESSFUL_CODE, "data": [11, 22, 33, 44]})
