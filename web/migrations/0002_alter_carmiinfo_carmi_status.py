# Generated by Django 5.0.3 on 2024-03-31 08:30

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("web", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="carmiinfo",
            name="carmi_status",
            field=models.BooleanField(default=False, verbose_name="卡密状态"),
        ),
    ]
