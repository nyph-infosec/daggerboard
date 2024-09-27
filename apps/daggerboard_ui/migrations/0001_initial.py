# Generated by Django 3.2.13 on 2024-09-17 04:17

from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Cpe',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('cpe', models.CharField(max_length=100)),
            ],
            options={
                'db_table': 'daggerboard_cpe',
            },
        ),
        migrations.CreateModel(
            name='Sbom',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('documentname', models.CharField(max_length=200)),
                ('vendorname', models.CharField(max_length=100)),
                ('creatororganization', models.CharField(max_length=100)),
                ('creatorcomment', models.CharField(max_length=8092)),
                ('uploadtime', models.DateTimeField(default=django.utils.timezone.now, verbose_name='Created At')),
                ('modtime', models.DateTimeField(auto_now=True)),
                ('filehash', models.CharField(blank=True, max_length=100)),
            ],
            options={
                'db_table': 'daggerboard_sbom',
            },
        ),
        migrations.CreateModel(
            name='SbomUpload',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('sbomfile', models.FileField(blank=True, upload_to='sbom/')),
                ('filename', models.CharField(blank=True, default='', max_length=100)),
                ('uploadtime', models.DateTimeField(default=django.utils.timezone.now, verbose_name='Created At')),
                ('sha1', models.CharField(blank=True, max_length=100)),
                ('job_id', models.CharField(blank=True, max_length=100)),
                ('sbomid_sbomupload', models.ForeignKey(db_column='sbomid_sbomupload', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='sbomupload', to='daggerboard_ui.sbom')),
            ],
            options={
                'db_table': 'daggerboard_sbomupload',
            },
        ),
        migrations.CreateModel(
            name='Package',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('packagename', models.CharField(max_length=100)),
                ('packageversion', models.CharField(max_length=50)),
                ('packagesupplier', models.CharField(max_length=50)),
                ('packagecomment', models.CharField(max_length=8092)),
                ('sbomid_packages', models.ForeignKey(db_column='sbomid_packages', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='packages_sbom', to='daggerboard_ui.sbom')),
            ],
            options={
                'db_table': 'daggerboard_package',
            },
        ),
        migrations.CreateModel(
            name='Cve',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('cve', models.CharField(max_length=30)),
                ('cve_sum', models.CharField(max_length=8092)),
                ('cvss3_score', models.CharField(max_length=30)),
                ('cvss3_severity', models.CharField(max_length=15)),
                ('cvss3_vector', models.CharField(max_length=70)),
                ('cve_exploit', models.CharField(max_length=8092, null=True)),
                ('cpeid_cve', models.ForeignKey(db_column='cpeid_cve', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='cves_cpe', to='daggerboard_ui.cpe')),
                ('packageid_cve', models.ForeignKey(db_column='packageid_cve', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='cves_package', to='daggerboard_ui.package')),
                ('sbomid_cve', models.ForeignKey(db_column='sbomid_cve', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='cves_sbom', to='daggerboard_ui.sbom')),
            ],
            options={
                'db_table': 'daggerboard_cve',
            },
        ),
        migrations.AddField(
            model_name='cpe',
            name='packageid_cpe',
            field=models.ForeignKey(db_column='packageid_cpe', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='cpes_package', to='daggerboard_ui.package'),
        ),
        migrations.AddField(
            model_name='cpe',
            name='sbomid_cpe',
            field=models.ForeignKey(db_column='sbomid_cpe', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='cpes_sbom', to='daggerboard_ui.sbom'),
        ),
    ]
