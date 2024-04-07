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
from django.urls import path, re_path
from web import views

urlpatterns = [
    # path("admin/", admin.site.urls),
    # path("home/", views.HomeView.as_view(), name="home"), # 反向解析，get请求带参
    # path("api/<str:version>/home/", views.HomeView.as_view(), name="home"),  # URL路由带参
    # re_path(r"^api/(?P<version>\w+)/home/$", views.HomeView.as_view(), name="home"),  # URL路由正则带参
    # path("api/home/", views.HomeView.as_view(), name="home"),  # 请求头中获取
    # path("login/", views.LoginView.as_view()),
    path("user/", views.UserView.as_view()),
    path("order/", views.OrderView.as_view()),
    path("avatar/", views.AvatarView.as_view()),
    # URL路由带参
    path("api/<str:version>/home/", views.HomeView.as_view(), name="home"),
    # 注册
    path("api/<str:version>/register/", views.RegisterView.as_view()),
    # 登录
    path("api/<str:version>/login/", views.LoginView.as_view()),
    # 卡密信息操作
    path("api/<str:version>/carmiinfo/", views.CarmiInfoView.as_view()),
    # 单个卡密信息操作
    path("api/<str:version>/carmiinfo/<str:carmi_code>", views.CarmiInfoDetailView.as_view()),
    # 所有卡密日志信息
    # path("api/<str:version>/carmilog/", views.CarmiLogView.as_view()),
    # 单个卡密日志信息
    # path("api/<str:version>/carmilog/<str:carmi_code>", views.CarmiLogDetailView.as_view()),
    # 用户购买与使用卡密
    path("api/<str:version>/usercarmi/", views.UserCarmiView.as_view()),

]
