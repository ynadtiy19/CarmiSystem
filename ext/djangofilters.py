from django_filters.rest_framework import DjangoFilterBackend
from django_filters import FilterSet, filters

from web.models import CarmiGenLog, CarmiBuyLog, CarmiInfo, UserInfo


class CarmiInfoFilterSet(FilterSet):
    carmi_code = filters.CharFilter(field_name="carmi_code", lookup_expr="exact")
    carmi_duration = filters.CharFilter(field_name="carmi_duration", lookup_expr="exact")
    carmi_buy_status = filters.CharFilter(field_name="carmi_buy_status", lookup_expr="exact")
    carmi_use_status = filters.CharFilter(field_name="carmi_use_status", lookup_expr="exact")
    # 大于等于
    carmi_duration_gte = filters.DateTimeFilter(field_name="carmi_duration", lookup_expr="gte")
    # 小于等于
    carmi_duration_lte = filters.DateTimeFilter(field_name="carmi_duration", lookup_expr="lte")

    class Meta:
        model = CarmiInfo
        fields = ["carmi_code", "carmi_duration", "carmi_buy_status", "carmi_use_status", "carmi_duration_gte",
                  "carmi_duration_lte"]


class CarmiGenLogFilterSet(FilterSet):
    carmi_code = filters.CharFilter(field_name="carmi_code__carmi_code", lookup_expr="exact")
    generating_user = filters.CharFilter(field_name="generating_user__username", lookup_expr="icontains")
    # 大于等于
    generating_time_gte = filters.DateTimeFilter(field_name="generating_time", lookup_expr="gte")
    # 小于等于
    generating_time_lte = filters.DateTimeFilter(field_name="generating_time", lookup_expr="lte")

    class Meta:
        model = CarmiGenLog
        fields = ["carmi_code", "generating_user", "generating_time_gte", "generating_time_lte"]


class CarmiBuyLogFilterSet(FilterSet):
    carmi_code = filters.CharFilter(field_name="carmi_code__carmi_code", lookup_expr="exact")
    buying_user = filters.CharFilter(field_name="buying_user__username", lookup_expr="icontains")
    # 大于等于
    buying_time_gte = filters.DateTimeFilter(field_name="buying_time", lookup_expr="gte")
    # 小于等于
    buying_time_lte = filters.DateTimeFilter(field_name="buying_time", lookup_expr="lte")

    class Meta:
        model = CarmiBuyLog
        fields = ["carmi_code", "buying_user", "buying_time_gte", "buying_time_lte"]


class UserInfoFilterSet(FilterSet):
    username = filters.CharFilter(field_name="username", lookup_expr="exact")
    role = filters.CharFilter(field_name="role", lookup_expr="exact")

    class Meta:
        model = UserInfo
        fields = ["username", "role"]
