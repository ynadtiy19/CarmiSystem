import random

from rest_framework.permissions import BasePermission
from ext import code


# 用户权限
class UserPermission(BasePermission):
    message = {"code": code.PERMISSION_CODE, "msg": "无权访问！"}

    def has_permission(self, request, view):
        if request.user.role == 3:
            return True
        return False

    def has_object_permission(self, request, view, obj):
        return True


# 会员权限
class VipPermission(BasePermission):
    message = {"code": code.PERMISSION_CODE, "msg": "用户无权访问！"}

    def has_permission(self, request, view):
        if request.user.role == 2:
            return True
        return False

    def has_object_permission(self, request, view, obj):
        return True


# 管理员权限
class ManagerPermission(BasePermission):
    message = {"code": code.PERMISSION_CODE, "msg": "只有管理员才能访问！"}

    def has_permission(self, request, view):
        if request.user.role == 1:
            return True
        return False

    def has_object_permission(self, request, view, obj):
        return True


class DocPermission(BasePermission):
    def has_permission(self, request, view):
        if request.user.role == 1 or request.user.role == 2:
            return True
        return False

    def has_object_permission(self, request, view, obj):
        return True

