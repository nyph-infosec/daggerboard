# Generated by Django 3.2.13 on 2024-09-17 04:17

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='DaggerBoardAPI',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('documentname', models.CharField(max_length=200)),
                ('vendorname', models.CharField(max_length=100)),
                ('critical_risk_count', models.IntegerField()),
                ('high_risk_count', models.IntegerField()),
                ('medium_risk_count', models.IntegerField()),
                ('low_risk_count', models.IntegerField()),
                ('risk_grade', models.TextField()),
                ('created_at', models.DateTimeField(auto_now=True)),
            ],
        ),
    ]