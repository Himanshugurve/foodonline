# Generated by Django 3.2.23 on 2023-11-16 10:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='role',
            field=models.PositiveIntegerField(blank=True, choices=[(2, 'Customer'), (1, 'Restaurant')], null=True),
        ),
    ]
