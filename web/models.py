import datetime

from django.db import models


# Create your models here.

class UserInfo(models.Model):
    """用户表"""
    username = models.CharField(verbose_name="用户名", max_length=32, db_index=True)
    password = models.CharField(verbose_name="密码", max_length=64)

    token = models.CharField(verbose_name="TOKEN", max_length=64, null=True, blank=True, db_index=True)

    role = models.IntegerField(verbose_name="角色", choices=((1, "管理员"), (2, "会员"), (3, "用户")), default=3)


class CarmiInfo(models.Model):
    """卡密信息表"""
    carmi_code = models.CharField(verbose_name="卡密", max_length=64, db_index=True, unique=True)
    carmi_duration = models.IntegerField(verbose_name="卡密时长")
    carmi_status = models.IntegerField(verbose_name="卡密状态", choices=((0, "未使用"), (1, "已使用")), default=0)


class CarmiGenLog(models.Model):
    """卡密生成记录"""
    carmi_code = models.ForeignKey(verbose_name="卡密", to="CarmiInfo", on_delete=models.CASCADE)
    generating_user = models.ForeignKey(verbose_name="生成用户", to="UserInfo", on_delete=models.CASCADE)
    generating_time = models.DateTimeField(verbose_name="生成时间", auto_now_add=True)


class CarmiUseLog(models.Model):
    """卡密使用记录"""
    carmi_code = models.ForeignKey(verbose_name="卡密", to="CarmiInfo", on_delete=models.CASCADE)
    using_machine = models.CharField(verbose_name="使用机器", max_length=64, null=True)
    using_time = models.DateTimeField(verbose_name="使用时间", null=True)
    due_time = models.DateTimeField(verbose_name="到期时间", null=True)
