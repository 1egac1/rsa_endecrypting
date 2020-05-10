import os
from getpass import getpass
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization 
from cryptography.hazmat.primitives.asymmetric import padding  
from cryptography.hazmat.primitives import hashes  
from cryptography.hazmat.primitives.serialization import load_pem_private_key  
from cryptography.hazmat.primitives.serialization import load_pem_public_key  

def acc_managment (passw):
    while True:
        ch = input("[1] Decrypt message \n[2] Encrypt message\n[3 or other]Exit\nWhat do you want to do?[num] ")
        if ch == "2":
            message = input("PUT YOUR MESSAGE >> ")
            pub_keys_list = os.listdir("pub_keys")
            for i in range(1, len(pub_keys_list)+1):
                print(str(i)+". "+pub_keys_list[i-1])
            path_encr_key = input("Num of the key >> ")
            PubKey = load_pem_public_key(open('pub_keys/'+pub_keys_list[int(path_encr_key)-1], 'rb').read(),default_backend())
            encrtext = PubKey.encrypt(
                bytes(message, encoding='utf-8'),
                padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                )
            )
            filename = input("Choose filename >> ")
            f = open("mess-s/" + filename, "wb")
            f.write(encrtext)
            f.close
        elif ch == "1":
            PrivKey = load_pem_private_key(open("priv_key/priv_key.pem", 'rb').read(),bytes(passw, encoding='utf-8'),default_backend())
            dir_list = os.listdir("mess-s")
            for i in range(1, len(dir_list)+1):
               print(str(i)+'. '+dir_list[i-1])
            choose = int(input("What mess you want to decrypt? "))
            opend = open('mess-s/'+dir_list[choose-1], 'rb')
            ciphertext = opend.read()
            d = PrivKey.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print("Message".center(60,"="))
            print(str(d)[2:len(str(d))-1])
            print("="*60)
        else:
            exit()


def register():
    os.mkdir("pub_key")
    os.mkdir("pub_keys")
    os.mkdir("priv_key")
    os.mkdir("mess-s")
    password = getpass("Create Password >> ")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()
    with open("priv_key/priv_key.pem", "wb") as f:  
        f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM, 
                    format=serialization.PrivateFormat.TraditionalOpenSSL, 
                    encryption_algorithm=serialization.BestAvailableEncryption(bytes(password, encoding='utf-8')),
                    )
                )
    f.close()

    with open("pub_key/pub_key.pem", "wb") as f:
        f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM, 
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                )
    f.close()
    acc_managment(password)


def log_in():
     password = getpass("Password >> ")
     acc_managment(password)

if __name__ == "__main__":
    ex = os.listdir('.')
    ex_bool = False
    for el in ex:
        if el == "pub_key":
            ex_bool = True
            break
    if ex_bool:
        log_in()
    else:
        register()
