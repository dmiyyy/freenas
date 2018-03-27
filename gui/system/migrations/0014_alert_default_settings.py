# -*- coding: utf-8 -*-
# Generated by Django 1.10.8 on 2017-12-04 16:49
from __future__ import unicode_literals

from django.db import migrations, models
import freenasUI.freeadmin.models.fields


class Migration(migrations.Migration):

    dependencies = [
        ('system', '0013_rename_consulalerts_to_alertservice'),
    ]

    operations = [
        migrations.CreateModel(
            name='AlertDefaultSettings',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('settings', freenasUI.freeadmin.models.fields.DictField()),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.RunSQL("INSERT INTO system_alertdefaultsettings (settings) values ('{}')"),
    ]