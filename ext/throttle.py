from rest_framework.throttling import SimpleRateThrottle
from django.core.cache import cache as default_cache


# 匿名用户的限流
class IpThrottle(SimpleRateThrottle):
    scope = "ip"
    # THROTTLE_RATES = {"5m": "5/m"}  # 访问频率
    cache = default_cache

    def get_cache_key(self, request, view):
        ident = self.get_ident(request)  # 获取IP地址（request的去请求头中寻找）

        return self.cache_format % {
            'scope': self.scope,
            'ident': ident
        }


# 用户的限流
class UserThrottle(SimpleRateThrottle):
    scope = "user"
    # THROTTLE_RATES = {"5m": "5/m"}  # 访问频率
    cache = default_cache

    # 获取唯一标识符（通过基类获取的IP来定义标识符）
    def get_cache_key(self, request, view):
        ident = request.user.pk  # 用户ID

        return self.cache_format % {
            'scope': self.scope,
            'ident': ident
        }


class VipThrottle(SimpleRateThrottle):
    scope = "vip"
    # THROTTLE_RATES = {"5m": "5/m"}  # 访问频率
    cache = default_cache

    def get_cache_key(self, request, view):
        ident = request.user.pk  # 用户ID

        return self.cache_format % {
            'scope': self.scope,
            'ident': ident
        }
