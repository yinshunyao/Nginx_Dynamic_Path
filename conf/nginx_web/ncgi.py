# -*-coding:utf-8-*- 
"""
提供给 Nginx 加密的URL解密接口
Author：yinshunyao
Date:2017/3/17 0017上午 11:00
"""
from binascii import b2a_hex, a2b_hex
from Crypto.Cipher import AES
from flup.server.fcgi import WSGIServer
import re
import os


class prpcrypt:
    """
    加密字段，例如.encrypt('192.168.1.180')  = 'fbc3ea6dc7455db5e01f76d1526d5369'
    """
    def __init__(self, key):
        self.key = key
        self.mode = AES.MODE_CBC

    # 加密函数，如果text不是16的倍数【加密文本text必须为16的倍数！】，那就补足为16的倍数
    def encrypt(self, text):
        cryptor = AES.new(self.key, self.mode, self.key)
        # 这里密钥key 长度必须为16（AES-128）、24（AES-192）、或32（AES-256）Bytes 长度.目前AES-128足够用
        length = 16
        count = len(text)
        add = length - (count % length)
        text += '\0' * add
        self.ciphertext = cryptor.encrypt(text)
        # 因为AES加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题
        # 所以这里统一把加密后的字符串转化为16进制字符串
        return b2a_hex(self.ciphertext)

    # 解密后，去掉补足的空格用strip() 去掉
    def decrypt(self, text):
        cryptor = AES.new(self.key, self.mode, self.key)
        plain_text = cryptor.decrypt(a2b_hex(text))
        return plain_text.rstrip('\0')


p = prpcrypt('cetc%^&*()123456')

port = '8999'


def _refresh_port():
    current_path = os.path.abspath(os.path.dirname(__file__))
    with open('{}/ncgi.ini'.format(current_path), 'r') as config:
        try:
            content = config.read()
            port_info = re.search('port=(.*)', content)
            if not port_info:
                pass
            else:
                global port
                port = port_info.groups()[0].strip()
        except:
            pass

_refresh_port()

print('the storage port is {}'.format(port))
cgi_port = 50001
print('the fast cgi port is {}'.format(cgi_port))


def parse_ip(environ, start_response):
    request_uri = environ.get('REQUEST_URI') or ''
    splits = request_uri.split('/')
    # http://8.7.27.8:8999/group1/M00/00/00/CAcbCFhI8jqAL-ScAABlmI0H0nM41.jpeg
    # 编码成 http://8.7.27.8:50000/f54b358c5d6bb0515f542dcbf43f0b4c/group1/M00/00/00/CAcbCFhI8jqAL-ScAABlmI0H0nM41.jpeg
    # 本接口将f54b358c5d6bb0515f542dcbf43f0b4c/group1/M00/00/00/CAcbCFhI8jqAL-ScAABlmI0H0nM41.jpeg
    # 解码还原成http://8.7.27.8:8999/group1/M00/00/00/CAcbCFhI8jqAL-ScAABlmI0H0nM41.jpeg
    if len(splits) < 3:
        print('unknow url:{}'.format(request_uri))
        start_response('500 Error', [])
    else:
        # global port
        try:
            url = 'http://{}:{}/{}'.format(p.decrypt(splits[1]), port, '/'.join(splits[2:]))
            # print('url:{}'.format(url))
            start_response('200 OK', [('url', url)])
        except Exception, e:
            print('parse the IP error:{}'.format(e))
            start_response('500 Error', [])

    return ['']

if __name__ == '__main__':
    WSGIServer(parse_ip, bindAddress=('127.0.0.1', cgi_port)).run()
