from django.db import models


# Create your models here.
class ReceiverRegistration(models.Model):
    UserName = models.CharField(max_length=100)
    Pwd = models.CharField(max_length=100)
    Name = models.CharField(max_length=100)
    Gender = models.CharField(max_length=50)
    Dob = models.DateTimeField(blank=True, null=True)
    Email = models.EmailField()
    MobileNo = models.CharField(max_length=50)
    Address = models.CharField(max_length=500)
    PinCode = models.CharField(max_length=50)
    Location = models.CharField(max_length=100)
    ProfileImg = models.CharField(max_length=500)
    PublicKey = models.CharField(max_length=100, null=True)
    Status = models.CharField(max_length=50)

    class Meta:
        db_table = "ReceiverRegistration"


class SenderRegistration(models.Model):
    UserName = models.CharField(max_length=100)
    Pwd = models.CharField(max_length=100)
    Name = models.CharField(max_length=100)
    Gender = models.CharField(max_length=50)
    Dob = models.DateTimeField(blank=True, null=True)
    Email = models.EmailField()
    MobileNo = models.CharField(max_length=50)
    Address = models.CharField(max_length=500)
    PinCode = models.CharField(max_length=50)
    Location = models.CharField(max_length=100)
    ProfileImg = models.CharField(max_length=500)
    PublicKey = models.CharField(max_length=100, null=True)
    Status = models.CharField(max_length=50)

    class Meta:
        db_table = "SenderRegistration"


class Transaction(models.Model):
    User = models.CharField(max_length=100)
    FileName = models.CharField(max_length=100)
    Task = models.CharField(max_length=100)
    TDate = models.DateTimeField(blank=True, null=True)

    class Meta:
        db_table = "Transaction"


class CloudServer(models.Model):
    Name = models.CharField(max_length=100)
    Pass = models.CharField(max_length=100)

    class Meta:
        db_table = "CloudServer"


class SharedKeys(models.Model):
    FileName = models.CharField(max_length=100)
    PublicKey = models.CharField(max_length=100)
    SecretKey = models.CharField(max_length=100)
    NewPublicKey = models.CharField(max_length=100)
    NewSecretKey = models.CharField(max_length=100)
    EDate = models.DateTimeField(blank=True, null=True)

    class Meta:
        db_table = "SharedKeys"


class Search(models.Model):
    User = models.CharField(max_length=100)
    Keyword = models.CharField(max_length=100)
    SDate = models.DateTimeField(blank=True, null=True)

    class Meta:
        db_table = "Search"


class KeyRequest(models.Model):
    Receiver = models.CharField(max_length=100)
    Sender = models.CharField(max_length=100)
    FileName = models.CharField(max_length=100)
    SecretKey = models.CharField(max_length=100)
    PublicKey = models.CharField(max_length=100, null=True)

    class Meta:
        db_table = "KeyRequest"


class SenderFiles(models.Model):
    FileName = models.CharField(max_length=100)
    Sender = models.CharField(max_length=100)
    FileContent = models.CharField(max_length=5000)
    PassContent = models.CharField(max_length=5000)
    CipherContent = models.CharField(max_length=100)
    Keyword = models.CharField(max_length=200)
    SecretKey = models.CharField(max_length=200)
    Trapdoor = models.CharField(max_length=200)
    UDate = models.DateTimeField(blank=True, null=True)

    class Meta:
        db_table = "SenderFiles"


class UploadData(models.Model):
    FileName = models.CharField(max_length=100)
    FileContent = models.CharField(max_length=5000)
    PassContent = models.CharField(max_length=5000)
    CipherContent = models.CharField(max_length=100)
    Keyword = models.CharField(max_length=200)
    SecretKey = models.CharField(max_length=200)
    Trapdoor = models.CharField(max_length=200)
    UDate = models.CharField(max_length=500)
    Sender = models.CharField(max_length=100)
    FStatus = models.CharField(max_length=50)

    class Meta:
        db_table = "UploadData"


class StopGuessKeys(models.Model):
    User = models.CharField(max_length=100)
    FileName = models.CharField(max_length=100)
    PublicKey = models.CharField(max_length=100)
    SecretKey = models.CharField(max_length=100)
    Trapdoor = models.CharField(max_length=500)
    KeyStatus = models.CharField(max_length=100)

    class Meta:
        db_table = "StopGuessKeys"


class Attacker(models.Model):
    User = models.CharField(max_length=100)
    FileName = models.CharField(max_length=100)
    AttackKey = models.CharField(max_length=100)
    ADate = models.DateTimeField(blank=True, null=True)
    AttackType = models.CharField(max_length=50)

    class Meta:
        db_table = "Attacker"

