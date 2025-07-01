from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64
import os

def utf8(s: bytes):
    return str(s, 'utf-8')

def copy_old_priv(file_name):
    with open(file_name, 'rb') as file:
        private_key_data = file.read()
        private_key = serialization.load_pem_private_key(private_key_data, password=None, backend=default_backend())
    return private_key

def copy_new_pub(file_name):
    with open(file_name, 'rb') as file:
        public_key_data = file.read()
        public_key = serialization.load_pem_public_key(public_key_data, backend=default_backend())
    return public_key

def utf8(s: bytes):
    return str(s, 'utf-8')

def decrypt_message(msg, key):
    decrypted_msg = key.decrypt(
        base64.b64decode(msg), 
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_msg

def encrypt_message(msg, key):
    encrypted_msg = base64.b64encode(key.encrypt(
        msg, 
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ))
    return encrypted_msg

def main():
    old_key = copy_old_priv('old_private_key.pem')
    new_key = copy_new_pub('new_public_key.pem')


    with open('user_profiles/aaron_diaz.bin', 'rb') as file:
        ok_data = file.read()
    decrypted_msg = decrypt_message(ok_data, old_key)
    print("Decryption for \"aaron_diaz.bin\"...\n")
    print(f'Decrypted message:\n{ utf8(decrypted_msg) }\n\n')
    os.mkdir('new_user_profiles')
    print("Encryption commencing for \"user_profiles\"...\n")
    for i in os.listdir('user_profiles'):
        file_path = os.path.join('user_profiles', i)
        with open(file_path, 'rb') as file:
            encrypted_data = file.read()
        
        decrypted_msg = decrypt_message(encrypted_data, old_key)
        encrypted_msg = encrypt_message(decrypted_msg, new_key)

        with open("new_user_profiles/"+i, 'wb') as file:
            file.write(encrypted_msg)
    
    print("Encryption completed. Files stored in \"new_user_profiles\"")
        
        

if __name__ == "__main__":
    main()