from rest_framework.pagination import PageNumberPagination, LimitOffsetPagination, CursorPagination
from rest_framework.response import Response

from ext import code


class MyPageNumberPagination(PageNumberPagination):
    # 单独重写返回的信息
    def get_paginated_response(self, data):
        return Response({
            'code': code.SUCCESSFUL_CODE,
            'count': self.page.paginator.count,
            'next': self.get_next_link(),
            'previous': self.get_previous_link(),
            'results': data,
        })


class MyLimitOffsetPagination(LimitOffsetPagination):
    # 单独重写返回的信息
    def get_paginated_response(self, data):
        return Response({
            'code': code.SUCCESSFUL_CODE,
            'count': self.count,
            'next': self.get_next_link(),
            'previous': self.get_previous_link(),
            'results': data
        })


class MyCursorPagination(CursorPagination):
    # 单独重写返回的信息
    def get_paginated_response(self, data):
        return Response({
            'code': code.SUCCESSFUL_CODE,
            'next': self.get_next_link(),
            'previous': self.get_previous_link(),
            'results': data,
        })


class CarmiInfoPageNumberPagination(MyPageNumberPagination):
    page_size = 10
    page_size_query_param = 'size'
    max_page_size = 100

    page_query_param = 'page'


class CarmiInfoLimitOffsetPagination(MyLimitOffsetPagination):
    default_limit = 10
    limit_query_param = 'limit'
    offset_query_param = 'offset'
    max_limit = 100


class CarmiInfoCursorPagination(MyCursorPagination):
    page_size = 10
    page_size_query_param = 'size'
    max_page_size = 100

    cursor_query_param = 'cursor'
    ordering = "id"


class CarmiGenLogCursorPagination(MyCursorPagination):
    page_size = 10
    page_size_query_param = 'size'
    max_page_size = 100

    cursor_query_param = 'cursor'
    ordering = '-generating_time'


class CarmiBuyPageNumberPagination(MyPageNumberPagination):
    page_size = 9
    page_size_query_param = 'size'
    max_page_size = 100

    page_query_param = 'page'


class CarmiBuyLogCursorPagination(MyCursorPagination):
    page_size = 10
    page_size_query_param = 'size'
    max_page_size = 100

    cursor_query_param = 'cursor'
    ordering = '-buying_time'


class CarmiUseLogCursorPagination(MyCursorPagination):
    page_size = 10
    page_size_query_param = 'size'
    max_page_size = 100

    cursor_query_param = 'cursor'
    ordering = '-using_time'


class UserInfoPageNumberPagination(MyPageNumberPagination):
    page_size = 10
    page_size_query_param = 'size'
    max_page_size = 100

    page_query_param = 'page'
