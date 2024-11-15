# Generated by Django 2.2.4 on 2024-03-02 07:56

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Attacker',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('User', models.CharField(max_length=100)),
                ('FileName', models.CharField(max_length=100)),
                ('AttackKey', models.CharField(max_length=100)),
                ('ADate', models.DateTimeField(blank=True, null=True)),
                ('AttackType', models.CharField(max_length=50)),
            ],
            options={
                'db_table': 'Attacker',
            },
        ),
        migrations.CreateModel(
            name='CloudServer',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('Name', models.CharField(max_length=100)),
                ('Pass', models.CharField(max_length=100)),
            ],
            options={
                'db_table': 'CloudServer',
            },
        ),
        migrations.CreateModel(
            name='KeyRequest',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('Receiver', models.CharField(max_length=100)),
                ('Sender', models.CharField(max_length=100)),
                ('FileName', models.CharField(max_length=100)),
                ('SecretKey', models.CharField(max_length=100)),
                ('PublicKey', models.CharField(max_length=100, null=True)),
            ],
            options={
                'db_table': 'KeyRequest',
            },
        ),
        migrations.CreateModel(
            name='ReceiverRegistration',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('UserName', models.CharField(max_length=100)),
                ('Pwd', models.CharField(max_length=100)),
                ('Name', models.CharField(max_length=100)),
                ('Gender', models.CharField(max_length=50)),
                ('Dob', models.DateTimeField(blank=True, null=True)),
                ('Email', models.EmailField(max_length=254)),
                ('MobileNo', models.CharField(max_length=50)),
                ('Address', models.CharField(max_length=500)),
                ('PinCode', models.CharField(max_length=50)),
                ('Location', models.CharField(max_length=100)),
                ('ProfileImg', models.CharField(max_length=500)),
                ('PublicKey', models.CharField(max_length=100, null=True)),
                ('Status', models.CharField(max_length=50)),
            ],
            options={
                'db_table': 'ReceiverRegistration',
            },
        ),
        migrations.CreateModel(
            name='Search',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('User', models.CharField(max_length=100)),
                ('Keyword', models.CharField(max_length=100)),
                ('SDate', models.DateTimeField(blank=True, null=True)),
            ],
            options={
                'db_table': 'Search',
            },
        ),
        migrations.CreateModel(
            name='SenderFiles',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('FileName', models.CharField(max_length=100)),
                ('Sender', models.CharField(max_length=100)),
                ('FileContent', models.CharField(max_length=5000)),
                ('PassContent', models.CharField(max_length=5000)),
                ('CipherContent', models.CharField(max_length=100)),
                ('Keyword', models.CharField(max_length=200)),
                ('SecretKey', models.CharField(max_length=200)),
                ('Trapdoor', models.CharField(max_length=200)),
                ('UDate', models.DateTimeField(blank=True, null=True)),
            ],
            options={
                'db_table': 'SenderFiles',
            },
        ),
        migrations.CreateModel(
            name='SenderRegistration',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('UserName', models.CharField(max_length=100)),
                ('Pwd', models.CharField(max_length=100)),
                ('Name', models.CharField(max_length=100)),
                ('Gender', models.CharField(max_length=50)),
                ('Dob', models.DateTimeField(blank=True, null=True)),
                ('Email', models.EmailField(max_length=254)),
                ('MobileNo', models.CharField(max_length=50)),
                ('Address', models.CharField(max_length=500)),
                ('PinCode', models.CharField(max_length=50)),
                ('Location', models.CharField(max_length=100)),
                ('ProfileImg', models.CharField(max_length=500)),
                ('PublicKey', models.CharField(max_length=100, null=True)),
                ('Status', models.CharField(max_length=50)),
            ],
            options={
                'db_table': 'SenderRegistration',
            },
        ),
        migrations.CreateModel(
            name='SharedKeys',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('FileName', models.CharField(max_length=100)),
                ('PublicKey', models.CharField(max_length=100)),
                ('SecretKey', models.CharField(max_length=100)),
                ('NewPublicKey', models.CharField(max_length=100)),
                ('NewSecretKey', models.CharField(max_length=100)),
                ('EDate', models.DateTimeField(blank=True, null=True)),
            ],
            options={
                'db_table': 'SharedKeys',
            },
        ),
        migrations.CreateModel(
            name='StopGuessKeys',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('User', models.CharField(max_length=100)),
                ('FileName', models.CharField(max_length=100)),
                ('PublicKey', models.CharField(max_length=100)),
                ('SecretKey', models.CharField(max_length=100)),
                ('Trapdoor', models.CharField(max_length=500)),
                ('KeyStatus', models.CharField(max_length=100)),
            ],
            options={
                'db_table': 'StopGuessKeys',
            },
        ),
        migrations.CreateModel(
            name='Transaction',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('User', models.CharField(max_length=100)),
                ('FileName', models.CharField(max_length=100)),
                ('Task', models.CharField(max_length=100)),
                ('TDate', models.DateTimeField(blank=True, null=True)),
            ],
            options={
                'db_table': 'Transaction',
            },
        ),
        migrations.CreateModel(
            name='UploadData',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('FileName', models.CharField(max_length=100)),
                ('FileContent', models.CharField(max_length=5000)),
                ('PassContent', models.CharField(max_length=5000)),
                ('CipherContent', models.CharField(max_length=100)),
                ('Keyword', models.CharField(max_length=200)),
                ('SecretKey', models.CharField(max_length=200)),
                ('Trapdoor', models.CharField(max_length=200)),
                ('UDate', models.CharField(max_length=500)),
                ('Sender', models.CharField(max_length=100)),
                ('FStatus', models.CharField(max_length=50)),
            ],
            options={
                'db_table': 'UploadData',
            },
        ),
    ]
