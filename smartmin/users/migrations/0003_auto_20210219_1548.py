# Generated by Django 2.2.17 on 2021-02-19 15:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0002_remove_failed_logins'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='failedlogin',
            name='user',
        ),
        migrations.AddField(
            model_name='failedlogin',
            name='username',
            field=models.CharField(default=None, max_length=256),
            preserve_default=False,
        ),
    ]
