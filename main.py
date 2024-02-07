from my_aes import *
from my_rsa import *
from sys import argv


help_doc='''帮助文档:
生成密钥：
command -c
command --createkey
加密文件:
command -e public_key_file to_encrypt_file
command --encrypt  public_key_file to_encrypt_file
解密文件:
command -d private_key_file encrypted_file
command --decrypt  private_key_file encrypted_file
查看帮助文档:
command  --help  
command  -h   '''





def main():
    if argv[1] == '--help' or argv[1] == '-h':
        print(help_doc)
    elif argv[1] == '-c' or argv[1] == '--createkey':
        create_key_rsa()
        print('创建密钥')
    elif argv[1] == '--encrypt' or argv[1] == '-e':
        encrypt_file(public_key_file=argv[2],to_encrypt_file=argv[3])
        print(f'加密文件,public_key_file={argv[2]},to_encrypt_file={argv[3]}')
    elif argv[1] == '--decrypt' or argv[1]=='-d':
        decrypt_file(private_key_file=argv[2],encryped_file=argv[3])
        print(f'解密文件,private_key_file={argv[2]},encrypted_file={argv[3]}')
    else:
        print(help_doc)



def encrypt_file(public_key_file, to_encrypt_file):
    with open(public_key_file, "rb") as f:
        pem_public=f.read()
    loaded_public_key = serialization.load_pem_public_key(
        pem_public,
        backend=None
    )


    # aes加密 源文件


    key_len_aes=32
    key = os.urandom(key_len_aes)  # Generate a random 256-bit (32-byte) key
    with open(to_encrypt_file, "rb") as f:
        data_to_encrypt_aes = f.read()  # Data to be encrypted (in bytes)
    # print("Original data aes:", data_to_encrypt_aes.decode('utf-8'))

    encrypted_data_aes = encrypt_AES(key, data_to_encrypt_aes)
    # print("Encrypted data aes:", encrypted_data_aes)





    # rsa加密aes_key



    # 加密aes_key
    data_to_encrypt_rsa = key  # Data to be encrypted (in bytes)
    # print('key',key)
    # print("Original data rsa:", data_to_encrypt_rsa)

    encrypted_data_rsa = encrypt_RSA(loaded_public_key, data_to_encrypt_rsa)
    # print("Encrypted data rsa:", encrypted_data_rsa)


    # 把加密后的aes_key和加密后的数据组合成新的文件
    new_data=encrypted_data_rsa+encrypted_data_aes
    # print('new_data:', new_data)
    with open(to_encrypt_file+'.encrypted', 'wb') as f:
        f.write(new_data)
    return new_data



def decrypt_file(private_key_file, encryped_file):
    # 获取数据头文件 和 数据文件
    with open(encryped_file,'rb') as f:
        encryped_data=f.read()
    # 被加密的aes_key
    encrpyted_rsa=encryped_data[:256]
    # 被加密的文件
    encrypted_aes=encryped_data[256::]

    # 获取rsa私钥对象
    with open(private_key_file,'rb') as f:   # 读取私钥文件
        pem_private=f.read()

    loaded_private_key = serialization.load_pem_private_key(      # 转换成私钥对象
        pem_private,
        password=None,
        backend=None
    )

    # 解密头部数据，得到aes的key
    encrypted_key= decrypt_RSA(loaded_private_key, encrpyted_rsa)



    # 用aes的key解密，得到源数据
    decrypted_data = decrypt_AES(encrypted_key, encrypted_aes)
    # print("Decrypted data:", decrypted_data)


    # 把源泉数据写入文件
    with open(encryped_file+'.dencrypted','wb') as f:
        f.write(decrypted_data)

    return decrypted_data


def create_key_rsa():
    # 创建key对象
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    key_len_aes = 32
    public_key = private_key.public_key()


    # 获取key对象的位数据
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


    # 写入key
    with open('private_key.pem', 'wb') as f:
        f.write(pem_private)
    with open('public_key.pem', 'wb') as f:
        f.write(pem_public)





if __name__ == '__main__':
    try:
        main()
    except:
        print(help_doc)