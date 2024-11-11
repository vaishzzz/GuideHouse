import os
import ast
import codecs
import random
import hashlib
import datetime
import pyaes, pbkdf2, binascii, secrets
from re import search
from datetime import datetime
from .sendmail import sendmail
from .honey import encrypt_data, decrypt_data
from .models import ReceiverRegistration
from .models import SenderRegistration
from .models import Transaction
from .models import CloudServer
from .models import SharedKeys
from .models import Search
from .models import KeyRequest
from .models import SenderFiles
from .models import UploadData
from .models import StopGuessKeys
from .models import Attacker
from django.db.models import Q
from django.db.models import Max
from django.db.models import Count
from django.contrib import messages
from django.shortcuts import render
from django.http import HttpResponse
from django.http import JsonResponse
from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from django.core.files.storage import FileSystemStorage

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Create your views here.
def index(request):
    return render(request, "StopGuessApp/index.html")


def receiver_register(request):
    if request.method == "POST":
        username = request.POST["userid"]
        pwd = request.POST["pass"]
        uname = request.POST["uname"]
        dob = request.POST["dob"]
        gender = request.POST["gender"]
        email = request.POST["email"]
        mobile = request.POST["mobile"]
        address = request.POST["address"]
        pincode = request.POST["pincode"]
        location = request.POST["location"]
        photo = request.FILES['imgFile']
        askQuery = ReceiverRegistration.objects.all().filter(UserName=username)
        if askQuery:
            messages.success(request, "Receiver Already Registered.")
        else:
            status = "Waiting"
            fs = FileSystemStorage()
            filename = fs.save(photo.name, photo)
            uploaded_file_url = fs.url(filename)
            insertQuery = ReceiverRegistration(UserName=username, Pwd=pwd, Name=uname, Gender=gender, Dob=dob, Email=email,
                                            MobileNo=mobile, Address=address, PinCode=pincode, Location=location,
                                            ProfileImg=uploaded_file_url, Status=status)
            insertQuery.save()
            if insertQuery.save:
                messages.success(request, "Receiver Registered Successfully.")
            else:
                messages.success(request, "Receiver Register Failed.")
    return render(request, "StopGuessApp/ReceiverRegister.html")


def receiver_login(request):
    if request.method == "POST":
        uname = request.POST['userid']
        pwd = request.POST['pass']
        pkey = request.POST['pkey']
        query = ReceiverRegistration.objects.all().filter(UserName=uname, Pwd=pwd)
        if query:
            for reg in query:
                status = reg.Status
            if status == "Authorized":
                query1 = ReceiverRegistration.objects.all().filter(UserName=uname, Pwd=pwd, PublicKey=pkey)
                if query1:
                    for reg1 in query1:
                        name = reg1.Name
                        username = reg1.UserName
                    request.session['receiver'] = name
                    request.session['uid'] = username
                    strReceiver = request.session['receiver']
                    askQuery = ReceiverRegistration.objects.all().filter(UserName=username, Pwd=pwd)
                    return render(request, "StopGuessApp/ReceiverHome.html", {"sessionUser": strReceiver, 'askQuery': askQuery})
                else:
                    messages.success(request, "Wrong Public Key, Try Again.")
                    return render(request, "StopGuessApp/ReceiverAuthorize2.html")
            elif status == "Waiting":
                messages.success(request, "Please Wait For Cloud Server To Authorize You !!!")
                return render(request, "StopGuessApp/ReceiverAuthorize1.html")
            else:
                messages.success(request, "Please Wait For Cloud Server To Authorize You !!!")
                return render(request, "StopGuessApp/ReceiverAuthorize.html")
        else:
            messages.success(request, "Invalid User Name and Password")
        return render(request, "StopGuessApp/WrongLogin.html")
    else:
        if 'receiver' in request.session:
            strReceiver = request.session['receiver']
            uname = request.session['uid']
            askQuery = ReceiverRegistration.objects.all().filter(UserName=uname, Name=strReceiver)
            return render(request, "StopGuessApp/ReceiverHome.html", {"sessionUser": strReceiver, 'askQuery': askQuery})
        else:
            return render(request, "StopGuessApp/ReceiverLogin.html")


def receiver_home(request):
    if 'receiver' in request.session:
        strReceiver = request.session['receiver']
        uname = request.session['uid']
        askQuery = ReceiverRegistration.objects.all().filter(UserName=uname, Name=strReceiver)
        if askQuery:
            return render(request, "StopGuessApp/ReceiverHome.html", {"sessionUser": strReceiver, "askQuery": askQuery})
    else:
        return render(request, "StopGuessApp/ReceiverLogin.html")


def receiver_profile(request):
    if 'receiver' in request.session:
        strReceiver = request.session['receiver']
        uname = request.session['uid']
        askQuery = ReceiverRegistration.objects.all().filter(UserName=uname, Name=strReceiver)
        if askQuery:
            return render(request, "StopGuessApp/ReceiverProfile.html", {"sessionUser": strReceiver, "askQuery": askQuery})
    else:
        return render(request, "StopGuessApp/ReceiverLogin.html")


def receiver_view_files(request):
    if 'receiver' in request.session:
        strReceiver = request.session['receiver']
        askQuery = UploadData.objects.all().order_by('id')
        if askQuery:
            return render(request, "StopGuessApp/ReceiverViewFiles.html", {"sessionUser": strReceiver, "askQuery": askQuery})
        else:
            return render(request, "StopGuessApp/ReceiverViewFiles.html", {"sessionUser": strReceiver})
    else:
        return render(request, "StopGuessApp/ReceiverLogin.html")


def receiver_search_files(request):
    if 'receiver' in request.session:
        strReceiver = request.session['receiver']
        uname = request.session['uid']
        if request.method == "POST":
            keyword = request.POST["txtKeyword"]
            now = datetime.now()
            cur_date = now.strftime("%Y-%m-%d %H:%M:%S")
            task = "Search"
            mySearch =""
            insert_query = Transaction(User=uname, FileName=keyword, Task=task, TDate=cur_date)
            insert_query.save()
            insert_query = Search(User=uname, Keyword=keyword, SDate=cur_date)
            insert_query.save()
            askQuery = UploadData.objects.all().order_by('id')
            if askQuery:
                for row in askQuery:
                    db_filename = row.FileName
                    db_content = row.FileContent
                    db_pass_content = row.PassContent
                    db_cipher_content = row.CipherContent
                    db_keyword = row.Keyword
                    db_secretkey = row.SecretKey
                    # Let us decrypt using our original password
                    # write data in a file.
                    with open('StopGuessApp/Upload/data.txt', 'w') as data_file:
                        data_file.write(db_content.decode("utf-8"))
                    data_file.close()
                    # write password in a file.
                    with open('StopGuessApp/Upload/pwd.txt', 'w') as pass_file:
                        pass_file.write(db_pass_content.decode("utf-8"))
                    pass_file.close()
                    honey_words = db_cipher_content.split(',')
                    ciphertext = int(honey_words[0])
                    trueSeed = int(honey_words[1])
                    mySearch = ""
                    # Let us decrypt using our original password
                    decrypted = decrypt_data(ciphertext, db_secretkey, trueSeed)
                    if search(keyword, decrypted) or search(keyword, db_keyword):
                        askQuery1 = UploadData.objects.all().filter(FileName=db_filename).order_by('id')
                        return render(request, "StopGuessApp/ReceiverSearchFiles.html", {"sessionUser": strReceiver, "askQuery1": askQuery1})
                    else:
                        mySearch ="File Not"
                if mySearch == "File Not":
                    return render(request, "StopGuessApp/ReceiverSearchFiles.html", {"sessionUser": strReceiver, "mySearch": mySearch})
            else:
                mySearch = "File Not"
                return render(request, "StopGuessApp/ReceiverSearchFiles.html", {"sessionUser": strReceiver, "mySearch": mySearch})
        else:
            return render(request, "StopGuessApp/ReceiverSearchFile.html", {"sessionUser": strReceiver})
    else:
        return render(request, "StopGuessApp/ReceiverLogin.html")


def receiver_search_file_result(request, filename):
    if 'receiver' in request.session:
        strReceiver = request.session['receiver']
        uname = request.session['uid']
        return render(request, "StopGuessApp/ReceiverDownloadSearchFile.html", {"sessionUser": strReceiver, "FileName": filename})
    else:
        return render(request, "StopGuessApp/ReceiverLogin.html")


def receiver_download_search_file(request):
    if 'receiver' in request.session:
        strReceiver = request.session['receiver']
        uname = request.session['uid']
        if request.method == "POST":
            filename = request.POST["filename"]
            if 'skey' not in request.POST:
                skey = ""
            else:
                skey = request.POST["skey"]
            attMessage = ""
            Message = ""
            trapdoor = ""
            publickey = ""
            status = ""
            askQuery = UploadData.objects.all().filter(FileName=filename)
            if askQuery:
                for row in askQuery:
                    skey = row.SecretKey
                    trapdoor = row.Trapdoor
                    status = row.FStatus
                if status == "Attacked":
                    attMessage = "File Content Attacked You Will Not Be Able To Download " + filename + " !!!"
                    return render(request, "StopGuessApp/DownloadFile.html", {"sessionUser": strReceiver, "Message": attMessage})
                else:
                    askQuery1 = KeyRequest.objects.all().filter(FileName=filename, Receiver=uname)
                    if askQuery1:
                        for row1 in askQuery1:
                            secretkey = row1.SecretKey
                            publickey = row1.PublicKey
                        if secretkey == "Share Query":
                            Message = "Secret Key Not Shared !!!"
                        elif secretkey == "No":
                            Message = "Secret Key Not Requested !!!"
                        else:
                            if publickey == "Generate Query":
                                Message = "Public Key Not Generated !!!"
                            elif publickey == "No":
                                Message = "Public Key Not Requested !!!"
                            else:
                                askQuery2 = StopGuessKeys.objects.all().filter(FileName=filename)
                                if askQuery2:
                                    for row2 in askQuery2:
                                        publickey = row2.PublicKey
                                        secretkey = row2.SecretKey
                                        key_status = row2.KeyStatus
                                    if publickey != "" and key_status == "0":
                                        if skey == secretkey:
                                            fileData = [filename, trapdoor, secretkey, publickey]
                                            return render(request, "StopGuessApp/DownloadFile.html",
                                                                  {"sessionUser": strReceiver, "fileData": fileData})
                                        else:
                                            attMessage = "Secret Key Attacked You Will Not Be Able To Download " + filename + " !!!"
                                            return render(request, "StopGuessApp/DownloadFile.html",
                                                                  {"sessionUser": strReceiver, "Message": attMessage})
                                    else:
                                        attMessage = "Public Key Attacked You Will Not Be Able To Download " + filename + " !!!"
                                        return render(request, "StopGuessApp/DownloadFile.html",
                                                          {"sessionUser": strReceiver, "Message": attMessage})
                    else:
                        Message = "Keys Not Requested !!!"
                        return render(request, "StopGuessApp/DownloadFile.html", {"sessionUser": strReceiver, "Message": Message})
            else:
                Message ="File Doesn't Exist !!!"
                return render(request, "StopGuessApp/DownloadFile.html", {"sessionUser": strReceiver, "Message": Message})
        else:
            return render(request, "StopGuessApp/ReceiverDownloadSearchFile.html", {"sessionUser": strReceiver})
    else:
        return render(request, "StopGuessApp/ReceiverLogin.html")


def receiver_downloaded_file(request):
    if 'receiver' in request.session:
        strReceiver = request.session['receiver']
        uname = request.session['uid']
        if request.method == "POST":
            filename = request.POST["filename"]
            trapdoor = request.POST["trapdoor"]
            secretkey = request.POST["secretkey"]
            publickey = request.POST["publickey"]
            now = datetime.now()
            cur_date = now.strftime("%Y-%m-%d %H:%M:%S")
            attMessage = ""
            Message = ""
            status = ""
            db_content = ""
            db_pass_content = ""
            db_cipher_content = ""
            askQuery = UploadData.objects.all().filter(FileName=filename, Trapdoor=trapdoor)
            if askQuery:
                for row in askQuery:
                    askQuery1 = StopGuessKeys.objects.all().filter(FileName=filename)
                    if askQuery1:
                        for row1 in askQuery1:
                            db_content = row.FileContent
                            db_pass_content = row.PassContent
                            db_cipher_content = row.CipherContent
                            dbPublicKey = row1.PublicKey
                            dbSecretKey = row1.SecretKey
                            if dbSecretKey == secretkey:
                                if dbPublicKey == publickey:
                                    now = datetime.now()
                                    cur_date = now.strftime("%Y-%m-%d %H:%M:%S")
                                    task = "Download"
                                    insert_query = Transaction(User=uname, FileName=filename, Task=task, TDate=cur_date)
                                    insert_query.save()
                                    # Let us decrypt using our original password
                                    decrypted_content = honey_decrypt(db_content, db_pass_content, db_cipher_content, secretkey)
                                    fileData = [decrypted_content]
                                    return render(request, "StopGuessApp/DownloadedFile.html",
                                                      {"sessionUser": strReceiver, "fileData": fileData})
                                else:
                                    status = "Public Key Attack"
                                    insert_query = Attacker(User=uname, FileName=filename, AttackKey=publickey,
                                                                   ADate=cur_date, AttackType=status)
                                    insert_query.save()
                                    att_update = UploadData.objects.filter(FileName=filename).update(FStatus="Attacked")
                                    key_update = StopGuessKeys.objects.filter(FileName=filename).update(KeyStatus="1")
                                    attMessage = "Public Key Mismatch !!!"
                                    return render(request, "StopGuessApp/DownloadedFile.html",
                                                      {"sessionUser": strReceiver, "Message": attMessage})
                            else:
                                status = "Secret Key Attack"
                                insert_query = Attacker(User=uname, FileName=filename, AttackKey=secretkey,
                                                        ADate=cur_date, AttackType=status)
                                insert_query.save()
                                att_update = UploadData.objects.filter(FileName=filename).update(FStatus="Attacked")
                                key_update = StopGuessKeys.objects.filter(FileName=filename).update(KeyStatus="1")
                                attMessage = "Secret Key Mismatch !!!"
                                return render(request, "StopGuessApp/DownloadedFile.html",
                                              {"sessionUser": strReceiver, "Message": attMessage})
                    else:
                        Message ="File Doesn't Exist !!!"
                        return render(request, "StopGuessApp/DownloadedFile.html", {"sessionUser": strReceiver, "Message": Message})
            else:
                status = "Trapdoor Generation Attack"
                insert_query = Attacker(User=uname, FileName=filename, AttackKey=trapdoor,
                                        ADate=cur_date, AttackType=status)
                insert_query.save()
                att_update = UploadData.objects.filter(FileName=filename).update(FStatus="Attacked")
                key_update = StopGuessKeys.objects.filter(FileName=filename).update(KeyStatus="1")
                attMessage = "Trapdoor Generation Mismatch !!!"
                return render(request, "StopGuessApp/DownloadedFile.html",
                              {"sessionUser": strReceiver, "Message": attMessage})
        else:
            return render(request, "StopGuessApp/ReceiverDownloadSearchFile.html", {"sessionUser": strReceiver})
    else:
        return render(request, "StopGuessApp/ReceiverLogin.html")


def receiver_req_publickey(request):
    if 'receiver' in request.session:
        strReceiver = request.session['receiver']
        uname = request.session['uid']
        if request.method == "POST":
            sendername = request.POST["sendername"]
            filename = request.POST["filename"]
            Message = ""
            publickey = ""
            status = "Requested"
            askQuery = UploadData.objects.all().filter(FileName=filename, Sender=sendername)
            if askQuery:
                askQuery1 = KeyRequest.objects.all().filter(Receiver=uname, Sender=sendername, FileName=filename)
                if askQuery1:
                    for row1 in askQuery1:
                        publickey = row1.PublicKey
                    if publickey == status:
                        Message = "Request Already Sent !!!"
                    elif publickey == "No":
                        keyUpdate = KeyRequest.objects.filter(Receiver=uname, Sender=sendername, FileName=filename).update(PublicKey=status)
                        Message = "Public Key Request Sent !!"
                    else:
                        Message = "Key Request Already Sent !!!"
                    return render(request, "StopGuessApp/ReceiverReqPublicKey.html",
                                  {"sessionUser": strReceiver, "Message": Message})
                else:
                    insertQuery = KeyRequest(Receiver=uname, Sender=sendername, FileName=filename, SecretKey="No", PublicKey=status)
                    insertQuery.save()
                    if insertQuery.save:
                        Message = "Public Key Request Sent !!"
                    return render(request, "StopGuessApp/ReceiverReqPublicKey.html",
                                  {"sessionUser": strReceiver, "Message": Message})
            else:
                Message = "File Doesn't Exist!!!"
                return render(request, "StopGuessApp/ReceiverReqPublicKey.html", {"sessionUser": strReceiver, "Message": Message})
        else:
            return render(request, "StopGuessApp/ReceiverReqPublicKey.html", {"sessionUser": strReceiver})
    else:
        return render(request, "StopGuessApp/ReceiverLogin.html")


def receiver_req_secretkey(request):
    if 'receiver' in request.session:
        strReceiver = request.session['receiver']
        uname = request.session['uid']
        if request.method == "POST":
            sendername = request.POST["sendername"]
            filename = request.POST["filename"]
            Message = ""
            secretkey = ""
            status = "Share Key"
            askQuery = UploadData.objects.all().filter(FileName=filename, Sender=sendername)
            if askQuery:
                askQuery1 = KeyRequest.objects.all().filter(Receiver=uname, Sender=sendername, FileName=filename)
                if askQuery1:
                    for row1 in askQuery1:
                        secretkey = row1.SecretKey
                    if secretkey == status:
                        Message = "Request Already Sent !!!"
                    elif secretkey == "No":
                        keyUpdate = KeyRequest.objects.filter(Receiver=uname, Sender=sendername, FileName=filename).update(SecretKey=status)
                        Message = "Secret Key Request Sent !!"
                    else:
                        Message = "Key Request Already Sent !!!"
                    return render(request, "StopGuessApp/ReceiverReqSecretKey.html",
                                  {"sessionUser": strReceiver, "Message": Message})
                else:
                    insertQuery = KeyRequest(Receiver=uname, Sender=sendername, FileName=filename, SecretKey=status, PublicKey="No")
                    insertQuery.save()
                    if insertQuery.save:
                        Message = "Secret Key Request Sent !!"
                    return render(request, "StopGuessApp/ReceiverReqSecretKey.html",
                                  {"sessionUser": strReceiver, "Message": Message})
            else:
                Message = "File Doesn't Exist!!!"
                return render(request, "StopGuessApp/ReceiverReqSecretKey.html", {"sessionUser": strReceiver, "Message": Message})
        else:
            return render(request, "StopGuessApp/ReceiverReqSecretKey.html", {"sessionUser": strReceiver})
    else:
        return render(request, "StopGuessApp/ReceiverLogin.html")


def receiver_res_publickey(request):
    if 'receiver' in request.session:
        strReceiver = request.session['receiver']
        uname = request.session['uid']
        if request.method == "POST":
            sendername = request.POST["sendername"]
            filename = request.POST["filename"]
            Message = ""
            publickey = ""
            status = "0"
            askQuery = UploadData.objects.all().filter(FileName=filename)
            if askQuery:
                askQuery1 = KeyRequest.objects.all().filter(Receiver=uname, FileName=filename)
                if askQuery1:
                    for row1 in askQuery1:
                        publickey = row1.PublicKey
                    if publickey == "NO":
                        Message = "Public Key Not Requested !!!"
                    elif publickey == "Requested":
                        Message = "Public Key Not Permitted !!!"
                    elif publickey == "Permitted":
                        askQuery2 = StopGuessKeys.objects.all().filter(User=sendername, FileName=filename)
                        if askQuery2:
                            for row2 in askQuery2:
                                db_publickey = row2.PublicKey
                                db_status = row2.KeyStatus
                            if db_status == "0":
                                Message = "Public Key : " + db_publickey
                            else:
                                Message = "Public Key Attacked !!!"
                    return render(request, "StopGuessApp/ReceiverResPublicKey.html", {"sessionUser": strReceiver, "Message": Message})
                else:
                    Message = "Public Key Not Requested !!!"
                    return render(request, "StopGuessApp/ReceiverResPublicKey.html", {"sessionUser": strReceiver, "Message": Message})
            else:
                Message = "File Not Found !!!"
                return render(request, "StopGuessApp/ReceiverResPublicKey.html", {"sessionUser": strReceiver, "Message": Message})
        else:
            return render(request, "StopGuessApp/ReceiverResPublicKey.html", {"sessionUser": strReceiver})
    else:
        return render(request, "StopGuessApp/ReceiverLogin.html")


def receiver_res_secretkey(request):
    if 'receiver' in request.session:
        strReceiver = request.session['receiver']
        uname = request.session['uid']
        if request.method == "POST":
            sendername = request.POST["sendername"]
            filename = request.POST["filename"]
            Message = ""
            secretkey = ""
            status = "Share Key"
            askQuery = UploadData.objects.all().filter(FileName=filename)
            if askQuery:
                askQuery1 = KeyRequest.objects.all().filter(Receiver=uname, FileName=filename)
                if askQuery1:
                    for row1 in askQuery1:
                        secretkey = row1.SecretKey
                    if secretkey == "Share Key":
                        Message = "Secret Key Not Shared !!!"
                    else:
                        askQuery2 = StopGuessKeys.objects.all().filter(User=sendername, FileName=filename)
                        if askQuery2:
                            for row2 in askQuery2:
                                db_secretkey = row2.SecretKey
                                db_status = row2.KeyStatus
                            if db_status == "0":
                                Message = "Secret Key : " + db_secretkey
                            else:
                                Message = "Secret Key Attacked !!!"
                    return render(request, "StopGuessApp/ReceiverResSecretKey.html", {"sessionUser": strReceiver, "Message": Message})
                else:
                    Message = "Secret Key Not Requested !!!"
                    return render(request, "StopGuessApp/ReceiverResSecretKey.html", {"sessionUser": strReceiver, "Message": Message})
            else:
                Message = "File Not Found !!!"
                return render(request, "StopGuessApp/ReceiverResSecretKey.html", {"sessionUser": strReceiver, "Message": Message})
        else:
            return render(request, "StopGuessApp/ReceiverResSecretKey.html", {"sessionUser": strReceiver})
    else:
        return render(request, "StopGuessApp/ReceiverLogin.html")


def receiver_download_file(request):
    if 'receiver' in request.session:
        strReceiver = request.session['receiver']
        uname = request.session['uid']
        attMessage = ""
        Message = ""
        secretkey = ""
        publickey = ""
        status = ""
        if request.method == "POST":
            filename = request.POST["filename"]
            if 'trapdoor' not in request.POST:
                trapdoor = ""
            else:
                trapdoor = request.POST["trapdoor"]
            secretkey = request.POST["secretkey"]
            publickey = request.POST["publickey"]
            now = datetime.now()
            cur_date = now.strftime("%Y-%m-%d %H:%M:%S")
            askQuery = UploadData.objects.all().filter(FileName=filename)
            if askQuery:
                for row in askQuery:
                    dbtrapdoor = row.Trapdoor
                    status = row.FStatus
                if status == "Attacked":
                    attMessage = "File Content Attacked You Will Not Be Able To Download " + filename + " !!!"
                    return render(request, "StopGuessApp/ReceiverDownloadFile.html", {"sessionUser": strReceiver, "Message": attMessage})
                else:
                    askQuery1 = KeyRequest.objects.all().filter(FileName=filename, Receiver=uname)
                    if askQuery1:
                        for row1 in askQuery1:
                            dbsecretkey = row1.SecretKey
                            dbpublickey = row1.PublicKey
                        if dbsecretkey == "Share Query":
                            Message = "SecretKey Key Not Generated !!!"
                        elif dbsecretkey == "No":
                            Message = "SecretKey Key Not Requested !!!"
                        else:
                            if dbpublickey == "Generate Query":
                                Message = "Public Key Not Generated !!!"
                            elif dbpublickey == "No":
                                Message = "Public Key Not Requested !!!"
                            else:
                                askQuery2 = StopGuessKeys.objects.all().filter(FileName=filename)
                                if askQuery2:
                                    for row2 in askQuery2:
                                        db_publickey = row2.PublicKey
                                        db_secretkey = row2.SecretKey
                                        db_trapdoor = row2.Trapdoor
                                        key_status = row2.KeyStatus
                                    if db_trapdoor == trapdoor and key_status == "0":
                                        if db_publickey == publickey:
                                            if db_secretkey == secretkey:
                                                fileData = [filename, trapdoor, secretkey, publickey]
                                                return render(request, "StopGuessApp/DownloadFile.html",
                                                                      {"sessionUser": strReceiver, "fileData": fileData})
                                            else:
                                                status = "Secret Key Attack"
                                                insert_query = Attacker(User=uname, FileName=filename, AttackKey=secretkey,
                                                                        ADate=cur_date, AttackType=status)
                                                insert_query.save()
                                                att_update = UploadData.objects.filter(FileName=filename).update(
                                                    FStatus="Attacked")
                                                key_update = StopGuessKeys.objects.filter(FileName=filename).update(
                                                    KeyStatus="1")
                                                attMessage = "Secret Key Attacked You Will Not Be Able To Download " + filename + " !!!"
                                                return render(request, "StopGuessApp/ReceiverDownloadFile.html",
                                                                      {"sessionUser": strReceiver, "Message": attMessage})
                                        else:
                                            status = "Public Key Attack"
                                            insert_query = Attacker(User=uname, FileName=filename, AttackKey=publickey,
                                                                    ADate=cur_date, AttackType=status)
                                            insert_query.save()
                                            att_update = UploadData.objects.filter(FileName=filename).update(
                                                FStatus="Attacked")
                                            key_update = StopGuessKeys.objects.filter(FileName=filename).update(
                                                KeyStatus="1")
                                            attMessage = "Public Key Attacked You Will Not Be Able To Download " + filename + " !!!"
                                            return render(request, "StopGuessApp/ReceiverDownloadFile.html",
                                                              {"sessionUser": strReceiver, "Message": attMessage})
                                    else:
                                        status = "Trapdoor Generation Attack"
                                        insert_query = Attacker(User=uname, FileName=filename, AttackKey=trapdoor,
                                                                ADate=cur_date, AttackType=status)
                                        insert_query.save()
                                        att_update = UploadData.objects.filter(FileName=filename).update(
                                            FStatus="Attacked")
                                        key_update = StopGuessKeys.objects.filter(FileName=filename).update(
                                            KeyStatus="1")
                                        attMessage = "Trapdoor Attacked You Will Not Be Able To Download " + filename + " !!!"
                                        return render(request, "StopGuessApp/ReceiverDownloadFile.html",
                                                          {"sessionUser": strReceiver, "Message": attMessage})
                    else:
                        Message = "Keys Not Requested !!!"
                        return render(request, "StopGuessApp/ReceiverDownloadFile.html", {"sessionUser": strReceiver, "Message": Message})
            else:
                Message ="File Doesn't Exist !!!"
                return render(request, "StopGuessApp/ReceiverDownloadFile.html", {"sessionUser": strReceiver, "Message": Message})
        else:
            return render(request, "StopGuessApp/ReceiverDownloadFile.html", {"sessionUser": strReceiver})
    else:
        return render(request, "StopGuessApp/ReceiverLogin.html")


def receiver_profile_image(request):
    if 'receiver' in request.session:
        strReceiver = request.session['receiver']
        uname = request.session['uid']
        if request.method == "POST":
            askQuery = ReceiverRegistration.objects.all().filter(UserName=uname)
            if askQuery:
                photo = request.FILES['imgFile']
                fs = FileSystemStorage()
                filename = fs.save(photo.name, photo)
                uploaded_file_url = fs.url(filename)
                profileUpdate = ReceiverRegistration.objects.filter(UserName=uname).update(ProfileImg=uploaded_file_url)
                if profileUpdate:
                    messages.success(request, "My Profile Image Updated Successfully.")
                    askQuery = ReceiverRegistration.objects.all().filter(UserName=uname)
                else:
                    messages.success(request, "My Profile Image Not Updated.")
        else:
            askQuery = ReceiverRegistration.objects.all().filter(UserName=uname)
        return render(request, "StopGuessApp/ReceiverChangeProfileImage.html", {"sessionUser": strReceiver, 'askQuery': askQuery})
    else:
        return render(request, "StopGuessApp/ReceiverLogin.html")


def receiver_logout(request):
    if 'receiver' in request.session:
        del request.session['receiver']
        for key in list(request.session.keys()):
            del request.session[key]
        messages.success(request, "Logged Out Successfully.")
        return render(request, "StopGuessApp/ReceiverLogin.html")
    else:
        return render(request, "StopGuessApp/ReceiverLogin.html")


def sender_register(request):
    if request.method == "POST":
        username = request.POST["userid"]
        pwd = request.POST["pass"]
        oname = request.POST["oname"]
        dob = request.POST["dob"]
        gender = request.POST["gender"]
        email = request.POST["email"]
        mobile = request.POST["mobile"]
        address = request.POST["address"]
        pincode = request.POST["pincode"]
        location = request.POST["location"]
        photo = request.FILES['imgFile']
        status = "Waiting"
        askQuery = SenderRegistration.objects.all().filter(UserName=username)
        if askQuery:
            messages.success(request, "Data Sender User Name Already Exits.")
        else:
            fs = FileSystemStorage()
            filename = fs.save(photo.name, photo)
            uploaded_file_url = fs.url(filename)
            insertQuery = SenderRegistration(UserName=username, Pwd=pwd, Name=oname, Gender=gender, Dob=dob, Email=email,
                                            MobileNo=mobile, Address=address, PinCode=pincode, Location=location, ProfileImg=uploaded_file_url, Status=status)
            insertQuery.save()
            if insertQuery.save:
                messages.success(request, "Data Sender Registered Successfully.")
            else:
                messages.success(request, "Data Sender Register Failed.")
    return render(request, "StopGuessApp/SenderRegister.html")


def sender_login(request):
    if request.method == "POST":
        uname = request.POST['userid']
        pwd = request.POST['pass']
        pkey = request.POST['pkey']
        query = SenderRegistration.objects.all().filter(UserName=uname, Pwd=pwd)
        if query:
            for reg in query:
                status = reg.Status
            if status == "Authorized":
                query1 = SenderRegistration.objects.all().filter(UserName=uname, Pwd=pwd, PublicKey=pkey)
                if query1:
                    for reg1 in query1:
                        name = reg1.Name
                        username = reg1.UserName
                    request.session['sender'] = name
                    request.session['oid'] = username
                    strSender = request.session['sender']
                    regSender = SenderRegistration.objects.all().filter(UserName=username, Pwd=pwd)
                    return render(request, "StopGuessApp/SenderHome.html", {"sessionSender": strSender, 'regSender': regSender})
                else:
                    messages.success(request, "Wrong Public Key, Try Again.")
                    return render(request, "StopGuessApp/SenderAuthorize2.html")
            elif status == "Waiting":
                messages.success(request, "Please Wait For Cloud Server To Authorize You !!!")
                return render(request, "StopGuessApp/SenderAuthorize1.html")
            else:
                messages.success(request, "Please Wait For Cloud Server To Authorize You !!!")
                return render(request, "StopGuessApp/SenderAuthorize.html")
        else:
            messages.success(request, "Invalid User Name and Password")
        return render(request, "StopGuessApp/WrongLogin.html")
    else:
        if 'sender' in request.session:
            strSender = request.session['sender']
            uname = request.session['oid']
            regSender = SenderRegistration.objects.all().filter(UserName=uname, Name=strSender)
            return render(request, "StopGuessApp/SenderHome.html", {"sessionSender": strSender, 'regSender': regSender})
        else:
            return render(request, "StopGuessApp/SenderLogin.html")


def sender_home(request):
    if 'sender' in request.session:
        strSender = request.session['sender']
        uname = request.session['oid']
        regSender = SenderRegistration.objects.all().filter(UserName=uname, Name=strSender)
        return render(request, "StopGuessApp/SenderHome.html", {"sessionSender": strSender, 'regSender': regSender})
    else:
        return render(request, "StopGuessApp/SenderLogin.html")


def upload_file(request):
    if 'sender' in request.session:
        strSender = request.session['sender']
        uname = request.session['oid']
        query = SenderRegistration.objects.all().filter(UserName=uname, Name=strSender)
        if query:
            for row in query:
                pkey = row.PublicKey
        skey = secretkey_generate(pkey)
        return render(request, "StopGuessApp/UploadFile.html", {"sessionSender": strSender, "skey": skey})
    else:
        return render(request, "StopGuessApp/SenderLogin.html")


def upload_files(request):
    if 'sender' in request.session:
        strSender = request.session['sender']
        uname = request.session['oid']
        if request.method == "POST":
            filename = request.POST["filename"]
            contents = request.POST["contents"]
            keyword = request.POST["keyword"]
            skey = request.POST["skey"]
            request.session['fname'] = filename
            uploadQuery = UploadData.objects.all().filter(FileName=filename)
            if uploadQuery:
                messages.success(request, "File Name Already Exists.")
            else:
                query = SenderRegistration.objects.all().filter(UserName=uname)
                if query:
                    for reg in query:
                        status = reg.Status
                        pkey = reg.PublicKey
                    if status == "Authorized":
                        trap = trapdoor_generate(keyword.strip(), skey)
                        # First let us encrypt secret message
                        cipher_data = encrypt_data(contents, skey)
                        with open('StopGuessApp/Upload/pwd.txt') as pass_file:
                            passContent = pass_file.read()
                        pass_file.close()
                        PEKS = [keyword, skey, trap, pkey, cipher_data]
                        return render(request, "StopGuessApp/UploadFiles.html",
                                      {"sessionSender": strSender, "file": filename, "cont": passContent, "PEKS": PEKS})
                    else:
                        messages.success(request, "Please Authorize To Cloud Server !!.")
                        return render(request, "StopGuessApp/UploadFile.html",
                                      {"sessionSender": strSender})
                else:
                    messages.success(request, "Data is not uploading.")
                    return render(request, "StopGuessApp/UploadFile.html",
                                  {"sessionSender": strSender})
            return render(request, "StopGuessApp/UploadFile.html", {"sessionSender": strSender})
        else:
            return render(request, "StopGuessApp/UploadFile.html", {"sessionSender": strSender})
    else:
        return render(request, "StopGuessApp/SenderLogin.html")


def uploaded_files(request):
    if 'sender' in request.session:
        strSender = request.session['sender']
        uname = request.session['oid']
        if request.method == "POST":
            filename = request.POST["filename"]
            keyword = request.POST["keyword"]
            skey = request.POST["skey"]
            trap = request.POST["trap"]
            pkey = request.POST["pkey"]
            cipher_data = request.POST["cipher_data"]
            now = datetime.now()
            cur_date = now.strftime("%Y-%m-%d %H:%M:%S")
            request.session['fname'] = filename
            # First let us encrypt secret message
            with open('StopGuessApp/Upload/data.txt') as data_file:
                contents = data_file.read()
            data_file.close()
            with open('StopGuessApp/Upload/pwd.txt') as pass_file:
                pass_content = pass_file.read()
            pass_file.close()
            encrypt_date = encrypt(cur_date, skey)
            task = "Upload"
            status = "Original"
            askQuery = SenderFiles.objects.all().filter(Sender=uname, FileName=filename)
            if askQuery:
                messages.success(request, "The File is Already Uploaded.")
            else:
                insert_query = Transaction(User=uname, FileName=filename, Task=task, TDate=cur_date)
                insert_query.save()
                insert_query = UploadData(FileName=filename, FileContent=contents, PassContent=pass_content, CipherContent=cipher_data, Keyword=keyword, SecretKey=skey, Trapdoor=trap, UDate=encrypt_date, Sender=uname, FStatus=status)
                insert_query.save()
                insert_query = SenderFiles(FileName=filename, Sender=uname, FileContent=contents, PassContent=pass_content, CipherContent=cipher_data, Keyword=keyword, SecretKey=skey, Trapdoor=trap, UDate=cur_date)
                insert_query.save()
                insert_query = StopGuessKeys(User=uname, FileName=filename, PublicKey=pkey, SecretKey=skey, Trapdoor=trap, KeyStatus="0")
                insert_query.save()
                if insert_query.save:
                    messages.success(request, "Data Uploaded Successfully !!!.")
                else:
                    messages.success(request, "Data is not Uploading.")
            return render(request, "StopGuessApp/UploadedFiles.html", {"sessionSender": strSender})
        else:
            return render(request, "StopGuessApp/UploadFile.html", {"sessionSender": strSender})
    else:
        return render(request, "StopGuessApp/SenderLogin.html")


def view_files(request):
    if 'sender' in request.session:
        strSender = request.session['sender']
        uname = request.session['oid']
        askQuery = UploadData.objects.all().filter(Sender=uname).order_by('id')
        if askQuery:
            return render(request, "StopGuessApp/ViewFiles.html", {"sessionSender": strSender, "askQuery": askQuery})
        else:
            return render(request, "StopGuessApp/ViewFiles.html", {"sessionSender": strSender})
    else:
        return render(request, "StopGuessApp/SenderLogin.html")


def viewed_files(request, filename):
    if 'sender' in request.session:
        strSender = request.session['sender']
        uname = request.session['oid']
        askQuery = UploadData.objects.all().filter(Sender=uname, FileName=filename).order_by('id')
        if askQuery:
            return render(request, "StopGuessApp/ViewedFiles.html", {"sessionSender": strSender, "askQuery": askQuery})
        else:
            return render(request, "StopGuessApp/ViewFiles.html", {"sessionSender": strSender})
    else:
        return render(request, "StopGuessApp/SenderLogin.html")


def verify_files(request):
    if 'sender' in request.session:
        strSender = request.session['sender']
        uname = request.session['oid']
        askQuery = UploadData.objects.all().filter(Sender=uname).order_by('id')
        if askQuery:
            return render(request, "StopGuessApp/VerifyFiles.html", {"sessionSender": strSender, "askQuery": askQuery})
        else:
            return render(request, "StopGuessApp/VerifyFiles.html", {"sessionSender": strSender})
    else:
        return render(request, "StopGuessApp/SenderLogin.html")


def verified_files(request, filename):
    if 'sender' in request.session:
        strSender = request.session['sender']
        askQuery = StopGuessKeys.objects.all().filter(FileName=filename)
        if askQuery:
            # for row in askQuery:
            #     d1Address = row.D1Address
            #     d2Address = row.D2Address
            return render(request, "StopGuessApp/VerifiedFiles.html", {"sessionSender": strSender, "askQuery": askQuery, "FileName": filename})
    else:
        return render(request, "StopGuessApp/SenderLogin.html")


def recover_files(request, filename):
    if 'sender' in request.session:
        strSender = request.session['sender']
        uname = request.session['oid']
        askQuery = SenderFiles.objects.all().filter(FileName=filename, Sender=uname)
        if askQuery:
            Query = StopGuessKeys.objects.all().filter(FileName=filename)
            if Query:
                for row in Query:
                    skey = row.SecretKey
                status = "Recovered"
                now = datetime.now()
                cur_date = now.strftime("%Y-%m-%d %H:%M:%S")
                recovUpdate = UploadData.objects.filter(FileName=filename).update(FStatus=status)
                recovUpdate = StopGuessKeys.objects.filter(FileName=filename).update(KeyStatus="0")
                transInsert = Transaction(User=uname, FileName=filename, Task=status, TDate=cur_date)
                transInsert.save()
                if recovUpdate:
                    messages.success(request, "File Recovered Successfully !!!.")
                else:
                    messages.success(request, "My File Not Recovered.")
                return render(request, "StopGuessApp/RecoverFiles.html", {"sessionSender": strSender})
    else:
        return render(request, "StopGuessApp/SenderLogin.html")


def sender_logout(request):
    if 'sender' in request.session:
        del request.session['sender']
        for key in list(request.session.keys()):
            del request.session[key]
        messages.success(request, "Logged Out Successfully.")
        return render(request, "StopGuessApp/SenderLogin.html")
    else:
        return render(request, "StopGuessApp/SenderLogin.html")


def cloud_login(request):
    if request.method == "POST":
        uname = request.POST['userid']
        pwd = request.POST['pass']
        askQuery = CloudServer.objects.all().filter(Name=uname, Pass=pwd)
        if askQuery:
            for reg in askQuery:
                name = reg.Name
            request.session['cloud'] = name
            strCloud = request.session['cloud']
            return render(request, "StopGuessApp/CloudHome.html", {"sessionCloud": strCloud, "askQuery": askQuery})
        else:
            messages.success(request, "Invalid User Name and Password")
        return render(request, "StopGuessApp/WrongLogin.html")
    else:
        if 'cloud' in request.session:
            strCloud = request.session['cloud']
            askQuery = CloudServer.objects.all().filter(Name=strCloud)
            if askQuery:
                return render(request, "StopGuessApp/CloudHome.html", {"sessionCloud": strCloud, "askQuery": askQuery})
        else:
            return render(request, "StopGuessApp/CloudLogin.html")


def cloud_home(request):
    if 'cloud' in request.session:
        strCloud = request.session['cloud']
        askQuery = CloudServer.objects.all().filter(Name=strCloud)
        if askQuery:
            return render(request, "StopGuessApp/CloudHome.html", {"sessionCloud": strCloud, "askQuery": askQuery})
    else:
        return render(request, "StopGuessApp/CloudLogin.html")


def cloud_view_senders(request):
    if 'cloud' in request.session:
        strCloud = request.session['cloud']
        askQuery = SenderRegistration.objects.all().order_by('id')
        if askQuery:
            return render(request, "StopGuessApp/CloudViewSenders.html", {"sessionCloud": strCloud, "askQuery": askQuery})
    else:
        return render(request, "StopGuessApp/CloudLogin.html")


def cloud_verify_sender(request, id):
    if 'cloud' in request.session:
        strCloud = request.session['cloud']
        strStatus = "Authorized"
        public_key = publickey_generate(id)
        emailQuery = SenderRegistration.objects.all().filter(id=id)
        if emailQuery:
            for row in emailQuery:
                strName = row.Name
                strEmail = row.Email
            strMessage = "Hai " + strName + " Your Registration Authorized.\nYour Public Key is : " + public_key
            ans = sendmail(strEmail, strMessage)
        statusUpdate = SenderRegistration.objects.filter(id=id).update(PublicKey=public_key, Status=strStatus)
        askQuery = SenderRegistration.objects.all().order_by('id')
        return render(request, "StopGuessApp/CloudViewSenders.html", {"sessionCloud": strCloud, "ans": ans, "askQuery": askQuery})
    else:
        return render(request, "StopGuessApp/CloudLogin.html")


def cloud_view_receivers(request):
    if 'cloud' in request.session:
        strCloud = request.session['cloud']
        askQuery = ReceiverRegistration.objects.all().order_by('id')
        if askQuery:
            return render(request, "StopGuessApp/CloudViewReceivers.html", {"sessionCloud": strCloud, "askQuery": askQuery})
    else:
        return render(request, "StopGuessApp/CloudLogin.html")


def cloud_verify_receiver(request, id):
    if 'cloud' in request.session:
        strCloud = request.session['cloud']
        strStatus = "Authorized"
        public_key = publickey_generate(id)
        emailQuery = ReceiverRegistration.objects.all().filter(id=id)
        if emailQuery:
            for row in emailQuery:
                strName = row.Name
                strEmail = row.Email
            strMessage = "Hai " + strName + " Your Registration Authorized.\nYour Public Key is : " + public_key
            ans = sendmail(strEmail, strMessage)
        statusUpdate = ReceiverRegistration.objects.filter(id=id).update(PublicKey=public_key, Status=strStatus)
        askQuery = ReceiverRegistration.objects.all().order_by('id')
        return render(request, "StopGuessApp/CloudViewReceivers.html", {"sessionCloud": strCloud, "ans": ans, "askQuery": askQuery})
    else:
        return render(request, "StopGuessApp/CloudLogin.html")


def cloud_sender_files(request):
    if 'cloud' in request.session:
        strCloud = request.session['cloud']
        askQuery = UploadData.objects.all().order_by('id')
        if askQuery:
            return render(request, "StopGuessApp/CloudSenderFiles.html", {"sessionCloud": strCloud, "askQuery": askQuery})
        else:
            return render(request, "StopGuessApp/CloudSenderFiles.html", {"sessionCloud": strCloud})
    else:
        return render(request, "StopGuessApp/CloudLogin.html")


def cloud_viewed_file(request, filename):
    if 'cloud' in request.session:
        strCloud = request.session['cloud']
        askQuery = UploadData.objects.all().filter(FileName=filename).order_by('id')
        if askQuery:
            return render(request, "StopGuessApp/CloudViewedFile.html", {"sessionCloud": strCloud, "askQuery": askQuery})
        else:
            return render(request, "StopGuessApp/CloudSenderFiles.html", {"sessionCloud": strCloud})
    else:
        return render(request, "StopGuessApp/CloudLogin.html")


def cloud_view_attackers(request):
    if 'cloud' in request.session:
        strCloud = request.session['cloud']
        askQuery = Attacker.objects.all().order_by('id')
        if askQuery:
            return render(request, "StopGuessApp/CloudViewAttackers.html", {"sessionCloud": strCloud, "askQuery": askQuery})
        else:
            return render(request, "StopGuessApp/CloudViewAttackers.html", {"sessionCloud": strCloud})
    else:
        return render(request, "StopGuessApp/CloudLogin.html")


def cloud_files_with_publickey(request):
    if 'cloud' in request.session:
        strCloud = request.session['cloud']
        askQuery = StopGuessKeys.objects.all().order_by('id')
        if askQuery:
            return render(request, "StopGuessApp/CloudFilesWithPublicKey.html",
                          {"sessionDevice": strCloud, "askQuery": askQuery})
        else:
            return render(request, "StopGuessApp/CloudFilesWithPublicKey.html", {"sessionDevice": strCloud})
    else:
        return render(request, "StopGuessApp/CloudLogin.html")


def cloud_publickey_permission(request):
    if 'cloud' in request.session:
        strCloud = request.session['cloud']
        askQuery = KeyRequest.objects.all().filter(~Q(PublicKey="null")).order_by('id')
        if askQuery:
            return render(request, "StopGuessApp/CloudPublicKeyPermission.html",
                          {"sessionDevice": strCloud, "askQuery": askQuery})
        else:
            return render(request, "StopGuessApp/CloudPublicKeyPermission.html", {"sessionDevice": strCloud})
    else:
        return render(request, "StopGuessApp/CloudLogin.html")


def cloud_publicKey_permission_granted(request, id, filename):
    if 'cloud' in request.session:
        strCloud = request.session['cloud']
        strStatus = "Permitted"
        keyUpdate = KeyRequest.objects.filter(id=id, FileName=filename).update(PublicKey=strStatus)
        askQuery = KeyRequest.objects.all().filter(~Q(PublicKey="null")).order_by('id')
        return render(request, "StopGuessApp/CloudPublicKeyPermission.html", {"sessionDevice": strCloud, "askQuery": askQuery})
    else:
        return render(request, "StopGuessApp/CloudLogin.html")


def cloud_share_secretkey(request):
    if 'cloud' in request.session:
        strCloud = request.session['cloud']
        askQuery = KeyRequest.objects.all().filter(~Q(SecretKey="null")).order_by('id')
        if askQuery:
            return render(request, "StopGuessApp/CloudShareSecretKey.html",
                          {"sessionDevice": strCloud, "askQuery": askQuery})
        else:
            return render(request, "StopGuessApp/CloudShareSecretKey.html", {"sessionDevice": strCloud})
    else:
        return render(request, "StopGuessApp/CloudLogin.html")


def cloud_shared_secretkey(request, id, filename):
    if 'cloud' in request.session:
        strCloud = request.session['cloud']
        keyQuery = StopGuessKeys.objects.filter(FileName=filename)
        if keyQuery:
            for row in keyQuery:
                secretkey = row.SecretKey
            keyUpdate = KeyRequest.objects.filter(id=id, FileName=filename).update(SecretKey=secretkey)
        askQuery = KeyRequest.objects.all().filter(~Q(SecretKey="null")).order_by('id')
        return render(request, "StopGuessApp/CloudShareSecretKey.html", {"sessionDevice": strCloud, "askQuery": askQuery})
    else:
        return render(request, "StopGuessApp/CloudLogin.html")


def cloud_attackers_graph(request):
    if 'cloud' in request.session:
        strCloud = request.session['cloud']
        legend = "Cloud File Attacker Graph"
        attack_type = (Attacker.objects.values('AttackType').annotate(tcount=Count('AttackType')))
        attack_user = (Attacker.objects.values('User').annotate(ucount=Count('User')))
        attack_file = (Attacker.objects.values('FileName').annotate(fcount=Count('FileName')))
        labels = list()
        values = list()
        for att_user in attack_user:
            user_count = att_user['ucount']
        for att_file in attack_file:
            file_count = att_file['fcount']
        for att_type in attack_type:
            labels.append(att_type['AttackType'])
        for item in labels:
            query = Attacker.objects.all().filter(AttackType=item)
            score = 0
            for row in query:
                score += user_count + file_count
            values.append(str(score))
        context = {"sessionDevice": strCloud, "labels": labels, "values": values, "legend": legend}
        return render(request, "StopGuessApp/CloudAttackersGraph.html", context)
    else:
        return render(request, "StopGuessApp/CloudLogin.html")


def cloud_comparison_graph(request):
    if 'cloud' in request.session:
        strCloud = request.session['cloud']
        legend = "Comparison of Performance with PAEKS & HEKS Schemes"
        keywords = (UploadData.objects.values('Keyword').annotate(kcount=Count('Keyword')))
        senders = (UploadData.objects.values('Sender').annotate(scount=Count('Sender')))
        upload_files = (UploadData.objects.values('FileName').annotate(fcount=Count('FileName')))
        labels = list()
        values = list()
        for sender in senders:
            sender_count = sender['scount']
        for att_file in upload_files:
            file_count = att_file['fcount']
        for keyword in keywords:
            labels.append(keyword['Keyword'])
        for item in labels:
            query = UploadData.objects.all().filter(Keyword=item)
            score = 0
            for row in query:
                score += sender_count + file_count
            values.append(str(score))
        context = {"sessionDevice": strCloud, "labels": labels, "values": values, "legend": legend}
        return render(request, "StopGuessApp/CloudComparisonGraph.html", context)
    else:
        return render(request, "StopGuessApp/CloudLogin.html")


def cloud_trapdoor_graph(request):
    if 'cloud' in request.session:
        strCloud = request.session['cloud']
        legend = "Trapdoor with PAEKS & HEKS Schemes"
        trapdoors = (UploadData.objects.values('Trapdoor').annotate(tcount=Count('Trapdoor')))
        senders = (UploadData.objects.values('Sender').annotate(scount=Count('Sender')))
        upload_files = (UploadData.objects.values('FileName').annotate(fcount=Count('FileName')))
        labels = list()
        values = list()
        for sender in senders:
            sender_count = sender['scount']
        for att_file in upload_files:
            file_count = att_file['fcount']
        for trapdoor in trapdoors:
            labels.append(trapdoor['Trapdoor'])
        for item in labels:
            query = UploadData.objects.all().filter(Trapdoor=item)
            score = 0
            for row in query:
                score += sender_count + file_count
            values.append(str(score))
        context = {"sessionDevice": strCloud, "labels": labels, "values": values, "legend": legend}
        return render(request, "StopGuessApp/CloudTrapdoorGraph.html", context)
    else:
        return render(request, "StopGuessApp/CloudLogin.html")


def cloud_logout(request):
    if 'cloud' in request.session:
        del request.session['cloud']
        for key in list(request.session.keys()):
            del request.session[key]
        messages.success(request, "Logged Out Successfully.")
        return render(request, "StopGuessApp/CloudLogin.html")
    else:
        return render(request, "StopGuessApp/CloudLogin.html")


def publickey_generate(id_pp):
    passwordSalt = os.urandom(8)
    key = pbkdf2.PBKDF2(id_pp, passwordSalt).read(8)
    return str(binascii.hexlify(key),'utf-8')


def secretkey_generate(pkey):
    passwordSalt = os.urandom(8)
    key = pbkdf2.PBKDF2(pkey, passwordSalt).read(8)
    return str(binascii.hexlify(key), 'utf-8')


def trapdoor_generate(word, pkey):
    trapdoor = word + pkey
    start_len = int(len(trapdoor)/2)
    end_len = int(len(trapdoor))
    trapdoor = trapdoor[start_len:end_len]
    result = hashlib.sha1(trapdoor.encode())
    return result.hexdigest()


def encrypt(plain_text, skey):
    # generate a random salt
    salt = get_random_bytes(AES.block_size)
    # use the Scrypt KDF to get a private key from the password
    secret_key = hashlib.scrypt(
        skey.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    # create cipher config
    cipher_config = AES.new(secret_key, AES.MODE_GCM)
    # return a dictionary with the encrypted text
    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(plain_text, 'utf-8'))
    return {
        'cipher_text': b64encode(cipher_text).decode('utf-8'),
        'salt': b64encode(salt).decode('utf-8'),
        'nonce': b64encode(cipher_config.nonce).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8')
    }


def decrypt(enc_dict, skey):
    # decode the dictionary entries from base64
    salt = b64decode(enc_dict['salt'])
    cipher_text = b64decode(enc_dict['cipher_text'])
    nonce = b64decode(enc_dict['nonce'])
    tag = b64decode(enc_dict['tag'])
    # generate the private key from the password and salt
    secret_key = hashlib.scrypt(
        skey.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    # create the cipher config
    cipher = AES.new(secret_key, AES.MODE_GCM, nonce=nonce)
    # decrypt the cipher text
    decrypted = cipher.decrypt_and_verify(cipher_text, tag)

    return decrypted


def honey_decrypt(file_content, pass_content, cipher_content, secretkey):
    # write data in a file.
    with open('StopGuessApp/Upload/data.txt', 'w') as data_file:
        data_file.write(file_content.decode("utf-8"))
    data_file.close()
    # write password in a file.
    with open('StopGuessApp/Upload/pwd.txt', 'w') as pass_file:
        pass_file.write(pass_content.decode("utf-8"))
    pass_file.close()
    honey_words = cipher_content.split(',')
    ciphertext = int(honey_words[0])
    trueSeed = int(honey_words[1])
    # Let us decrypt using our original password
    decrypted = decrypt_data(ciphertext, secretkey, trueSeed)
    return decrypted