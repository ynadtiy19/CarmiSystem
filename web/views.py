import uuid

import redis
from django.db.models import Count
from django.http import JsonResponse
from django.utils import timezone

from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet
from rest_framework.mixins import (
    ListModelMixin, CreateModelMixin, RetrieveModelMixin, UpdateModelMixin,
    DestroyModelMixin
)
from rest_framework.exceptions import Throttled, ValidationError, ParseError
from rest_framework.parsers import JSONParser, FormParser, FileUploadParser
from rest_framework.negotiation import DefaultContentNegotiation
from rest_framework.pagination import PageNumberPagination, LimitOffsetPagination
from rest_framework.decorators import action
from .models import UserInfo, CarmiInfo, CarmiGenLog, CarmiBuyLog, CarmiUseLog

from web import models
from ext import code
from ext.per import UserPermission, VipPermission, ManagerPermission
from ext.view import MyAPIView, ORPerAPIView, MyGenericViewSet, ORPerGenericViewSet
from ext.serializers import CarmiInfoSerializer, RegisterSerializer, LoginSerializer, \
    CarmiGenLogSerializer, CarmiBuySerializer, CarmiBuyLogSerializer, UserInfoSerializer, CarmiBuyDetailSerializer, \
    CarmiUseSerializer, CarmiUseLogSerializer
from ext.throttle import IpThrottle, UserThrottle, VipThrottle
from ext.hook import HookSerializer
from ext.paginations import CarmiInfoPageNumberPagination, CarmiInfoLimitOffsetPagination, CarmiInfoCursorPagination, \
    CarmiGenLogCursorPagination, CarmiBuyLogCursorPagination, UserInfoPageNumberPagination, \
    CarmiBuyPageNumberPagination, CarmiUseLogCursorPagination
from ext.djangofilters import CarmiGenLogFilterSet, CarmiBuyLogFilterSet, CarmiInfoFilterSet, UserInfoFilterSet, \
    CarmiUseLogFilterSet


def test_cors(request):
    return JsonResponse({'msg': 'CORS is ok'})


class CarmiInfoView(ORPerGenericViewSet):
    """卡密信息操作"""
    permission_classes = [VipPermission, ManagerPermission]  # 管理员和会员
    throttle_classes = [VipThrottle]

    # 条件筛选
    # filter_backends = [DjangoFilterBackend,]
    filterset_class = CarmiInfoFilterSet

    # 先找没买的,再找没使用的,最后找id最小即最早的卡密
    # queryset = models.CarmiInfo.objects.all().order_by("carmi_buy_status", "carmi_use_status", "id")
    queryset = models.CarmiInfo.objects.all()
    serializer_class = CarmiInfoSerializer

    # 卡密信息的获取
    def list(self, request, *args, **kwargs):
        # 获取数据库中数据
        # queryset = self.get_queryset()
        queryset = self.filter_queryset(self.get_queryset())

        # 分页器
        pg = CarmiInfoCursorPagination()
        pager_queryset = pg.paginate_queryset(queryset=queryset, request=request, view=self)

        # 序列化
        ser = self.get_serializer(instance=pager_queryset, many=True)

        # 版本控制
        if request.version == "1.0":
            context = {"code": code.SUCCESSFUL_CODE, "data": ser.data}
            return Response(context, content_type="application/json;charset=utf-8")
        elif request.version == "2.0":
            return pg.get_paginated_response(data=ser.data)

    # 传入生成个数和天数
    def create(self, request, *args, **kwargs):
        # 更新创建时间
        # models.CarmiInfo.objects.all().update(creat_time=datetime.datetime.now(), end_time=None)
        ser = self.get_serializer(data=request.data, many=False)
        if ser.is_valid():
            # 获取验证通过的数据
            validated_data = ser.validated_data

            # 从 validated_data 中获取生成卡密的数量和每个卡密的天数
            generate_nums = validated_data['generate_nums']
            carmi_duration = validated_data['carmi_duration']
            if generate_nums <= 0 & carmi_duration <= 0:
                return Response(
                    {"code": code.CARMIGEN_CODE, "error": "卡密生成失败！", "detail": "卡密数量或者天数不能为0！"})

            # 批量生成卡密并保存到数据库
            generated_carmis = []
            for _ in range(generate_nums):
                new_carmi = CarmiInfo.objects.create(
                    carmi_code=str(uuid.uuid4()).replace('-', ''),  # 生成唯一的卡密代码
                    carmi_duration=carmi_duration,
                    carmi_buy_status=0,  # 设置初始状态为未购买
                    carmi_use_status=0,  # 设置初始状态为未使用
                )
                generated_carmis.append(new_carmi)
            # 获取当前用户实例（假设根据用户名获取用户实例）
            generating_user = UserInfo.objects.get(username=request.user.username)

            # 批量创建生成记录并保存到数据库
            gen_logs = [CarmiGenLog(
                carmi_code=carmi,
                generating_user=generating_user,
                generating_time=timezone.now()  # 使用当前时间作为生成时间
            ) for carmi in generated_carmis]
            CarmiGenLog.objects.bulk_create(gen_logs)
            # 序列化生成的卡密信息
            serialized_data = self.get_serializer(generated_carmis, many=True).data

            return Response({"code": code.SUCCESSFUL_CODE, "data": serialized_data})
        else:
            return Response({"code": code.CARMIGEN_CODE, "error": "卡密生成失败！", "detail": ser.errors})

    def retrieve(self, request, *args, **kwargs):
        # 获取卡密信息
        carmi_code = kwargs.get("carmi_code")  # viewset里面默认获取pk
        # 获取数据库中数据
        instance = models.CarmiInfo.objects.filter(carmi_code=carmi_code).first()
        if not instance:
            return Response({"code": code.NODATA_CODE, "error": "卡密不存在！"})
        # 序列化
        ser = self.get_serializer(instance=instance, many=False)
        context = {"code": code.SUCCESSFUL_CODE, "data": ser.data}
        return Response(context)

    def destroy(self, request, *args, **kwargs):
        # 获取卡密信息
        carmi_code = kwargs.get("carmi_code")
        # 获取数据库中数据
        # instance = models.CarmiInfo.objects.filter(carmi_code=carmi_code).first()
        # instance = self.get_queryset()

        try:
            instance = self.get_queryset().get(carmi_code=carmi_code)
            # 序列化
            ser = self.get_serializer(instance=instance, many=False)
            deleted_data = ser.data
            # 删除找到的卡密信息
            self.perform_destroy(instance)

            context = {"code": code.SUCCESSFUL_CODE, "data": deleted_data}
            return Response(context)
        except CarmiInfo.DoesNotExist:
            return Response({"code": code.NODATA_CODE, "error": "卡密不存在！"})

    def perform_destroy(self, instance):
        instance.delete()


"""
class CarmiInfoDetailView(ORPerAPIView):
    # 单卡密信息操作
    permission_classes = [ManagerPermission, VipPermission]  # 管理员和会员
    throttle_classes = [VipThrottle]

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
        """


class CarmiGenLogView(ORPerGenericViewSet):
    """生成卡密日志信息操作"""
    # 三大认证
    permission_classes = [VipPermission, ManagerPermission]  # 管理员和会员
    throttle_classes = [VipThrottle]

    # 条件筛选
    # filter_backends = [DjangoFilterBackend,]
    filterset_class = CarmiGenLogFilterSet

    # 获取数据
    queryset = models.CarmiGenLog.objects.all().order_by("-generating_time")
    serializer_class = CarmiGenLogSerializer

    def list(self, request, *args, **kwargs):
        # 更新创建时间
        # models.CarmiInfo.objects.all().update(creat_time=datetime.datetime.now(), end_time=None)
        # 获取数据库中数据，并且按照generating_time的时间降序排列，并且using_time为空的放在最上面
        # queryset = self.get_queryset()
        queryset = self.filter_queryset(self.get_queryset())

        # 分页器
        pg = CarmiGenLogCursorPagination()
        pager_queryset = pg.paginate_queryset(queryset=queryset, request=request, view=self)

        # 序列化
        ser = self.get_serializer(instance=pager_queryset, many=True)
        # context = {"code": code.SUCCESSFUL_CODE, "data": ser.data}
        # return Response(context)
        return pg.get_paginated_response(data=ser.data)


class CarmiBuyView(ORPerGenericViewSet):
    """购买卡密操作"""
    permission_classes = [UserPermission, VipPermission, ManagerPermission]  # 用户和管理员和会员
    throttle_classes = [UserThrottle]

    # 条件筛选
    # filter_backends = [DjangoFilterBackend,]
    # filterset_class = CarmiInfoFilterSet

    # 根据卡密时长排序,如何根据卡密id最早生成的先被购买
    queryset = models.CarmiInfo.objects.all().order_by("-carmi_duration").filter(carmi_buy_status=0)
    serializer_class = CarmiBuyDetailSerializer

    def list(self, request, *args, **kwargs):
        """获取可以购买卡密的信息
        :param: None

        :return: Json -> List<Map> -> {"carmi_duration": 120,"carmi_counts": 6}
        """
        # 获取卡密时长和对应数量的字典列表
        carmi_duration_counts = self.get_queryset().values('carmi_duration').annotate(
            carmi_counts=Count('carmi_duration'))

        # 实例化分页器
        pg = CarmiBuyPageNumberPagination()

        # 对查询结果进行分页
        pager_queryset = pg.paginate_queryset(queryset=carmi_duration_counts, request=request, view=self)

        # 将字典列表转换为更易于处理的格式
        # carmi_duration_info = {entry['carmi_duration']: entry['count'] for entry in carmi_duration_counts}

        # 返回分页后的结果
        return pg.get_paginated_response(pager_queryset)

        # print(carmi_duration_counts)
        # 将字典列表转换为更易于处理的格式
        # carmi_duration_info = {entry['carmi_duration']: entry['count'] for entry in carmi_duration_counts}
        # print(carmi_duration_info)

        # return Response(carmi_duration_counts)

    def create(self, request, *args, **kwargs):
        # 根据卡密时长和卡密数量购买
        # {"carmi_duration":30,"carmi_counts":4,"carmi_buy_counts":2}
        ser = CarmiBuySerializer(data=request.data, many=False)
        ser.is_valid(raise_exception=True)
        # 获取验证通过的数据
        # 从 validated_data 中获取传入的购买的卡密时长和购买数量,从而进行购买
        carmi_duration = ser.validated_data.get('carmi_duration')
        carmi_counts = ser.validated_data.get('carmi_counts')
        carmi_buy_counts = ser.validated_data.get('carmi_buy_counts')
        # 根据时长和数量筛选卡密
        buyed_carmis = models.CarmiInfo.objects.filter(carmi_duration=carmi_duration, carmi_buy_status=0)[
                       :carmi_buy_counts]

        if not buyed_carmis.exists():
            return Response({'detail': '该时长的卡密已全部购买'}, status=status.HTTP_400_BAD_REQUEST)

        # 循环遍历buyed_carmis列表，将其carmi_buy_status属性修改为1
        for carmi in buyed_carmis:
            carmi.carmi_buy_status = 1
            carmi.save()

        # 获取当前用户实例（假设根据用户名获取用户实例）
        buying_user = UserInfo.objects.get(username=request.user.username)

        # 批量创建生成记录并保存到数据库
        buy_logs = [CarmiBuyLog(
            carmi_code=carmi,
            buying_user=buying_user,
            buying_time=timezone.now()  # 使用当前时间作为生成时间
        ) for carmi in buyed_carmis]
        CarmiBuyLog.objects.bulk_create(buy_logs)
        # 序列化生成的卡密信息
        serialized_data = self.get_serializer(buyed_carmis, many=True).data

        return Response({"code": code.SUCCESSFUL_CODE, "data": serialized_data})

    def partial_update(self, request, *args, **kwargs):
        # 购买具体单个卡密
        # 获取卡密
        carmi_code = kwargs.get("carmi_code")
        # 通过部分更新伪造购买请求
        carmi = self.get_queryset().filter(carmi_code=carmi_code).first()

        # 检查是否已经购买
        if carmi.carmi_buy_status == 1:
            return Response({'detail': '该卡密已经购买'}, status=status.HTTP_400_BAD_REQUEST)

        # 进行部分更新
        carmi.carmi_buy_status = 1
        carmi.save()

        # 获取当前用户实例（假设根据用户名获取用户实例）
        buying_user = UserInfo.objects.get(username=request.user.username)

        # 更新购买数据表
        buy_logs = [CarmiBuyLog(
            carmi_code=carmi,
            buying_user=buying_user,
            buying_time=timezone.now()  # 使用当前时间作为生成时间
        )]
        CarmiBuyLog.objects.bulk_create(buy_logs)

        # 返回部分更新后的数据
        serializer = CarmiBuyDetailSerializer(instance=carmi)
        return Response(serializer.data)


class CarmiBuyLogView(ORPerGenericViewSet):
    """用户购买卡密日志信息操作"""
    # 三大认证
    permission_classes = [UserPermission, VipPermission, ManagerPermission]  # 用户、管理员和会员
    throttle_classes = [VipThrottle]

    # 条件筛选
    # filter_backends = [DjangoFilterBackend,]
    filterset_class = CarmiBuyLogFilterSet

    # 获取数据
    queryset = models.CarmiBuyLog.objects.all().order_by("-buying_time")
    serializer_class = CarmiBuyLogSerializer

    def list(self, request, *args, **kwargs):
        # 更新创建时间
        # models.CarmiInfo.objects.all().update(creat_time=datetime.datetime.now(), end_time=None)
        # 获取数据库中数据，并且按照generating_time的时间降序排列，并且using_time为空的放在最上面
        # queryset = self.get_queryset()
        queryset = self.filter_queryset(self.get_queryset())

        # 分页器
        pg = CarmiBuyLogCursorPagination()
        pager_queryset = pg.paginate_queryset(queryset=queryset, request=request, view=self)

        # 序列化
        ser = self.get_serializer(instance=pager_queryset, many=True)
        # context = {"code": code.SUCCESSFUL_CODE, "data": ser.data}
        # return Response(context)
        return pg.get_paginated_response(data=ser.data)


class CarmiUseView(GenericViewSet):
    """用户使用卡密"""
    authentication_classes = []  # 不需要token认证
    permission_classes = []  # 不需要权限
    throttle_classes = [IpThrottle]  # 没有了token表明身份,只能通过ip来限流

    queryset = models.CarmiInfo.objects.all()
    serializer_class = CarmiUseSerializer

    # r = redis.StrictRedis(host='localhost', port=6379, db=1, password='yaung')
    r = redis.StrictRedis(host='10.0.8.17', port=6379, db=1, password='yaung')

    def list(self, request, *args, **kwargs):
        """验证机器码的可用性
        :param: machine_code:机器码,

        :return: 登陆成功/登陆失败
        """
        # using_machine = request.data.get("using_machine")
        using_machine = request.query_params.get("using_machine")
        # 查看redis中是否存在这个机器码
        if self.r.exists(using_machine):
            return Response({"code": code.SUCCESSFUL_CODE, "detail": "登陆成功！"})
        return Response({"code": code.MACHINE_LOGIN_FAIL_CODE, "detail": "登陆失败！请先充值！"}, status=status.HTTP_400_BAD_REQUEST)

    def create(self, request, *args, **kwargs):
        """使用卡密
        :param: carmi_code:卡密号码,
                machine_code:机器码,

        :return: 卡密使用成功/卡密已经使用过了
        """
        # 获取验证通过的数据
        # 获取卡密和机器码
        # url中获取参数
        carmi_code = request.query_params.get("carmi_code")
        using_machine = request.query_params.get("using_machine")
        # 94efab65b7fe4096af6a0ac3ac3eea5f
        # carmi_code = request.data.get("carmi_code")
        # 08:00:20:0A:8C:6D
        # using_machine = request.data.get("using_machine")
        # print(carmi_code, using_machine)

        # 判断卡密是否存在
        carmi = self.get_queryset().filter(carmi_code=carmi_code).first()
        if carmi:
            """先修改数据信息，更新数据表"""
            # print(carmi)
            # 检查是否已经购买
            if carmi.carmi_use_status == 1:
                return Response({"code": code.CARMIUSE_USED_CODE,'detail': '该卡密已经使用过了！'}, status=status.HTTP_400_BAD_REQUEST)
            # 进行部分更新
            carmi.carmi_use_status = 1
            carmi.save()

            # 计算due_time到期时间,30
            due_time = timezone.now() + timezone.timedelta(seconds=carmi.carmi_duration * 60 * 60 * 24)
            print(timezone.now())
            print(due_time)

            # 更新使用数据表
            use_logs = [CarmiUseLog(
                carmi_code=carmi,
                using_machine=using_machine,
                using_time=timezone.now(),  # 使用当前时间作为生成时间
                due_time=due_time
            )]
            CarmiUseLog.objects.bulk_create(use_logs)

            """将机器码存储到redis中，并且设置好到期时间"""
            # 判断当前机器码是否已经存在于redis当中
            if self.r.exists(using_machine):
                # 获取机器码key的到期时间
                due_time = self.r.ttl(using_machine)
                # 根据carmi.carmi_duration增加到期时间
                self.r.expire(using_machine, due_time + carmi.carmi_duration * 60 * 60 * 24)
            else:
                self.r.set(using_machine, carmi_code, ex=carmi.carmi_duration * 60 * 60 * 24)

            # 返回部分更新后的数据
            # serializer = self.get_serializer(carmi)
            # return Response(serializer.data)
            return Response({"code": code.SUCCESSFUL_CODE, "detail": "卡密使用成功"})
        else:
            return Response({"code": code.CARMIUSE_LOSE_CODE,'detail': '卡密不存在！'}, status=status.HTTP_400_BAD_REQUEST)


class CarmiUseLogView(ORPerGenericViewSet):
    """用户使用卡密日志信息操作"""
    # 三大认证
    permission_classes = [UserPermission, VipPermission, ManagerPermission]  # 用户、管理员和会员
    throttle_classes = [VipThrottle]

    # 条件筛选
    # filter_backends = [DjangoFilterBackend,]
    filterset_class = CarmiUseLogFilterSet

    # 获取数据
    queryset = models.CarmiUseLog.objects.all().order_by("-using_time")
    serializer_class = CarmiUseLogSerializer

    def list(self, request, *args, **kwargs):
        # 更新创建时间
        # models.CarmiInfo.objects.all().update(creat_time=datetime.datetime.now(), end_time=None)
        # 获取数据库中数据，并且按照generating_time的时间降序排列，并且using_time为空的放在最上面
        # queryset = self.get_queryset()
        queryset = self.filter_queryset(self.get_queryset())

        # 分页器
        pg = CarmiUseLogCursorPagination()
        pager_queryset = pg.paginate_queryset(queryset=queryset, request=request, view=self)

        # 序列化
        ser = self.get_serializer(instance=pager_queryset, many=True)
        # context = {"code": code.SUCCESSFUL_CODE, "data": ser.data}
        # return Response(context)
        return pg.get_paginated_response(data=ser.data)


class RegisterView(MyAPIView):
    """用户注册"""
    authentication_classes = []  # 不需要token认证
    permission_classes = []  # 无权限限制
    throttle_classes = [IpThrottle, ]  # ip流

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
        ser1 = LoginSerializer(instance=instance)

        return Response({"code": code.SUCCESSFUL_CODE, "token": token, "role": ser1.data["role"]})


class UserInfoView(UpdateModelMixin, ORPerGenericViewSet):
    """用户信息操作"""
    permission_classes = [VipPermission, ManagerPermission]  # 管理员和会员
    throttle_classes = [VipThrottle]

    # 条件筛选
    # filter_backends = [DjangoFilterBackend,]
    filterset_class = UserInfoFilterSet

    queryset = models.UserInfo.objects.all()
    serializer_class = UserInfoSerializer

    def list(self, request, *args, **kwargs):
        # 获取数据库中数据
        # queryset = self.get_queryset()
        queryset = self.filter_queryset(self.get_queryset())

        # 分页器
        pg = UserInfoPageNumberPagination()
        pager_queryset = pg.paginate_queryset(queryset=queryset, request=request, view=self)

        # 序列化
        ser = self.get_serializer(instance=pager_queryset, many=True)
        # context = {"code": code.SUCCESSFUL_CODE, "data": ser.data}
        # return Response(context)
        return pg.get_paginated_response(data=ser.data)

    def retrieve(self, request, *args, **kwargs):
        # 获取用户信息
        pk = kwargs.get("pk")  # viewset里面默认获取pk
        # 获取数据库中数据
        instance = models.UserInfo.objects.filter(username=pk).first()
        if not instance:
            return Response({"code": code.NODATA_CODE, "error": "用户不存在！"})
        # 序列化
        ser = self.get_serializer(instance=instance, many=False)
        context = {"code": code.SUCCESSFUL_CODE, "data": ser.data}
        return Response(context)

    # def update(self, request, *args, **kwargs):
    #     # 获取用户信息
    #     username = kwargs.get("username")  # viewset里面默认获取pk
    #     # 获取数据库中数据
    #     instance = models.UserInfo.objects.filter(username=username).first()
    #     if not instance:
    #         return Response({"code": code.NODATA_CODE, "error": "用户不存在！"})
    #     instance = self.get_object()
    #     serializer = self.get_serializer(instance=instance, data=request.data, partial=True)
    #     serializer.is_valid(raise_exception=True)
    #     self.perform_update(serializer)
    #     return Response(serializer.data)


"""class HomeView(MyAPIView):
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
        return Response({"code": code.SUCCESSFUL_CODE, "data": [11, 22, 33, 44]})"""
