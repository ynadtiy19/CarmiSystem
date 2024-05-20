from rest_framework.exceptions import Throttled
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet

from ext import code

"""
采用或关系的权限认证
"""


# 重写限流的提示方法
class MyAPIView(APIView):
    def throttled(self, request, wait):
        detail = "请求过多!请等待{:}秒后再次尝试！".format(int(wait))
        code1 = code.THROTTLE_CODE
        raise Throttled(wait=None, detail=detail, code=code1)


class ORPerAPIView(MyAPIView):
    def check_permissions(self, request):
        no_permission_object = []  # 保存没有权限的对象
        for permission in self.get_permissions():
            if permission.has_permission(request, self):
                return
            else:
                no_permission_object.append(permission)

        # 都没有权限执行这个抛出异常
        self.permission_denied(
            request,
            message=getattr(no_permission_object[0], 'message', None),
            code=getattr(no_permission_object[0], 'code', None)
        )


# 重写限流的提示方法
class MyGenericViewSet(GenericViewSet):
    def throttled(self, request, wait):
        detail = "请求过多!请等待{:}秒后再次尝试！".format(int(wait))
        code1 = code.THROTTLE_CODE
        raise Throttled(wait=None, detail=detail, code=code1)


class ORPerGenericViewSet(MyGenericViewSet):
    def check_permissions(self, request):
        no_permission_object = []  # 保存没有权限的对象
        for permission in self.get_permissions():
            if permission.has_permission(request, self):
                return
            else:
                no_permission_object.append(permission)

        # 都没有权限执行这个抛出异常
        self.permission_denied(
            request,
            message=getattr(no_permission_object[0], 'message', None),
            code=getattr(no_permission_object[0], 'code', None)
        )
