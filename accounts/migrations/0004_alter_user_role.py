# Generated by Django 3.2.23 on 2023-11-23 04:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0003_auto_20231122_1600'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='role',
            field=models.PositiveIntegerField(blank=True, choices=[(2, 'Customer'), (1, 'Vendor')], null=True),
        ),
    ]
