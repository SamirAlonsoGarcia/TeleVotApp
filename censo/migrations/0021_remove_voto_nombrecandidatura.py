# Generated by Django 5.1.5 on 2025-06-26 17:02

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('censo', '0020_usuario_primera_vez'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='voto',
            name='nombreCandidatura',
        ),
    ]
