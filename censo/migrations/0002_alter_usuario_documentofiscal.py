# Generated by Django 5.1.5 on 2025-05-24 22:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('censo', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='usuario',
            name='DocumentoFiscal',
            field=models.CharField(max_length=12, unique=True),
        ),
    ]
