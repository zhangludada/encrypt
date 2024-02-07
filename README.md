## how to use
```python3
# 使用虚拟环境
source .venv/bin/activate
# 生成密钥：
python3 main.py  -c
python3 main.py  --createkey
# 加密文件:
python3 main.py  -e public_key_file to_encrypt_file
python3 main.py  --encrypt  public_key_file to_encrypt_file
# 解密文件:
python3 main.py  -d private_key_file encrypted_file
python3 main.py  --decrypt  private_key_file encrypted_file
# 查看帮助文档:
python3 main.py   --help  
python3 main.py   -h   
```

