"""
URL configuration for CarmiSystem project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
# from django.contrib import admin
from django.urls import path, re_path, include
from rest_framework import routers
from rest_framework.documentation import include_docs_urls
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

from ext.per import DocPermission
from web import views

schema_view = get_schema_view(
    openapi.Info(
        title="CarmiSystem API接口文档",
        default_version='1.0',
        description="描述信息",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="1422699629@qq.com"),
        license=openapi.License(name="协议版本"),
    ),
    public=True,
    # authentication_classes=[],
    permission_classes=[DocPermission],
)

# router = routers.SimpleRouter()
# router.register(r"carmiinfo", views.CarmiInfoView)

urlpatterns = [
    # path("admin/", admin.site.urls),
    # path("home/", views.HomeView.as_view(), name="home"), # 反向解析，get请求带参
    # path("api/<str:version>/home/", views.HomeView.as_view(), name="home"),  # URL路由带参
    # re_path(r"^api/(?P<version>\w+)/home/$", views.HomeView.as_view(), name="home"),  # URL路由正则带参
    # path("api/home/", views.HomeView.as_view(), name="home"),  # 请求头中获取
    # path("login/", views.LoginView.as_view()),
    # path("user/", views.UserView.as_view()),
    # path("order/", views.OrderView.as_view()),
    # path("avatar/", views.AvatarView.as_view()),
    # URL路由带参
    # path("api/<str:version>/home/", views.HomeView.as_view(), name="home"),
    path("test_cors/", views.test_cors),
    path('doc/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path("docs/", include_docs_urls(title="CarmiSystem API接口文档")),
    # 注册
    path("api/<str:version>/register/", views.RegisterView.as_view()),
    # 登录
    path("api/<str:version>/login/", views.LoginView.as_view()),
    # 用户管理
    path("api/<str:version>/userinfo/", views.UserInfoView.as_view({"get": "list"})),
    path("api/<str:version>/userinfo/<str:pk>",
         views.UserInfoView.as_view({"get": "retrieve", "put": "update", "patch": "partial_update"})),
    # 卡密信息操作
    path("api/<str:version>/carmiinfo/",
         views.CarmiInfoView.as_view({"get": "list", "post": "create"})),
    path("api/<str:version>/carmiinfo/<str:carmi_code>",
         views.CarmiInfoView.as_view({"get": "retrieve", "delete": "destroy"})),
    # path('api/<str:version>/', include(router.urls)),
    # 生成卡密日志信息
    path("api/<str:version>/carmigenlog/", views.CarmiGenLogView.as_view({"get": "list"})),
    # path("api/<str:version>/carmigenlog/<str:carmi_code>", views.CarmiGenLogView.as_view(
    #     {"get": "retrieve", "put": "update", "patch": "partial_update", "delete": "destory"})),
    # 购买卡密
    path("api/<str:version>/carmibuy/", views.CarmiBuyView.as_view({"get": "list", "post": "create"})),
    path("api/<str:version>/carmibuy/<str:carmi_code>", views.CarmiBuyView.as_view({"patch": "partial_update"})),
    # 购买卡密日志信息
    path("api/<str:version>/carmibuylog/", views.CarmiBuyLogView.as_view({"get": "list"})),

    # 使用卡密
    # path("api/<str:version>/usercarmi/", views.UseCarmiView.as_view({"get": "list"})),
    # path("api/<str:version>/carmiuse/<str:carmi_code>/<str:machine_code>",
    #      views.CarmiUseView.as_view({"patch": "partial_update"})),
    # 使用卡密日志信息

]
