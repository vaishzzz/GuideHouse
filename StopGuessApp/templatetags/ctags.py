import ast

from django import template

register = template.Library()
from StopGuessApp.models import UploadData
from StopGuessApp.views import decrypt
from StopGuessApp.honey import decrypt_data


@register.simple_tag()
def getdate(fid):
    query = UploadData.objects.all().filter(id=fid)
    if query:
        for row in query:
            db_date = row.UDate
            db_skey = row.SecretKey
        # Let us decrypt using our original password
        decrypted = decrypt(ast.literal_eval(bytes.decode(db_date)), db_skey)
    return bytes.decode(decrypted)


@register.simple_tag()
def getcontents(fid):
    query = UploadData.objects.all().filter(id=fid)
    if query:
        for row in query:
            db_content = row.FileContent
            db_pass_content = row.PassContent
            db_cipher_content = row.CipherContent
            db_skey = row.SecretKey
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
        # Let us decrypt using our original password
        decrypted = decrypt_data(ciphertext, db_skey, trueSeed)
    return decrypted

