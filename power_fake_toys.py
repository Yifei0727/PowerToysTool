#!/usr/bin/env python
# -*- coding: utf-8 -*-

import codecs
import random
import struct
import sys

import slowDES
from slowDES import triple_des, des
from slowSM4 import SM4

__all__ = ['generate_one']


def generate_data(byte_len):
    # type: (int)->bytes
    """
    产生指定长度随机数据
    :param byte_len: 产生的长度
    :return: 随机数据
    """
    return random.randbytes(byte_len)


def generate_num(num_char):
    # type: (int)->str
    """
    产生指定长度随机数字串
    :param num_char: 数字字符个数
    :return: 数字串
    """
    buf = []
    for i in range(num_char):
        buf.append(str(random.randint(0, 9)))
    return ''.join(buf)


def generate_pan():
    return generate_num(16)


def generate_pin():
    return generate_num(6)


def pad_pin_format(pin, block_size):
    assert 4 <= len(pin) <= 12
    assert block_size == 8 or block_size == 16
    return '0%X%s%s' % (len(pin), pin, 'F' * (block_size * 2 - 2 - len(pin)))


def pad_pan_format(pan, block_size):
    pan12 = get_pan_12_from_pan(pan)
    assert block_size == 8 or block_size == 16
    return '%s%s' % ('0' * (block_size * 2 - 12), pan12)


def get_pan_12_from_pan(pan):
    assert 16 == len(pan)
    return pan[3:-1]


def xor_pin_with_pan(pin_block, pan_block):
    assert len(pin_block) == len(pan_block)
    b1 = codecs.decode(pin_block, 'hex')
    b2 = codecs.decode(pan_block, 'hex')
    buf = []
    if sys.version_info[0] == 2:
        for a, b in zip(b1, b2):
            buf.append(struct.pack('B', (ord(a) ^ ord(b))))
        return str(codecs.encode(b''.join(buf), 'hex')).upper()
    elif sys.version_info[0] == 3:
        for a, b in zip(b1, b2):
            buf.append(struct.pack('B', (a ^ b)))
        return str(codecs.encode(b''.join(buf), 'hex'), encoding='ascii').upper()
    else:
        raise EnvironmentError("Python Version Not Support")


def test_pan_12():
    assert '234567890123' == get_pan_12_from_pan('6212345678901234')


def test_pad_pin():
    assert '06123456FFFFFFFF' == pad_pin_format('123456', 8)
    assert '06123456FFFFFFFFFFFFFFFFFFFFFFFF' == pad_pin_format('123456', 16)


def test_pad_pan():
    assert '0000234567890123' == pad_pan_format('6212345678901234', 8)
    assert '00000000000000000000234567890123' == pad_pan_format('6212345678901234', 16)


def test_pin_pan():
    assert '' == xor_pin_with_pan('', '')


def generate_one(key=None):
    # type: ([None,str])->object
    """
    生成一条数据记录
    :param key: 加密密钥，如果没有则不加密
    :return: 产生的随机记录
    """
    rec = {}
    rec.update(PAN=generate_pan())
    rec.update(PIN=generate_pin())
    rec.update(PinAccount=get_pan_12_from_pan(rec.get("PAN")))
    rec.update(PlainPINBlock_GJ=xor_pin_with_pan(pad_pin_format(rec["PIN"], 8), pad_pan_format(rec["PAN"], 8)))
    rec.update(PlainPINBlock_GM=xor_pin_with_pan(pad_pin_format(rec["PIN"], 16), pad_pan_format(rec["PAN"], 16)))
    if key is None:
        return rec
    if len(key) == 8:
        engine = des(key)
    elif len(key) == 24:
        engine = triple_des(key)
    elif len(key) == 16:
        engine = SM4(codecs.encode(key, 'hex'), SM4.ECB)
        cb = engine.encrypt(codecs.decode(rec['PlainPINBlock_GM'], 'hex'))
        rec.update(CipherPINBlock_GM=str(codecs.encode(cb, 'hex')).upper())
        engine = triple_des(key)
    else:
        raise ValueError("Invalid Key")

    engine.setKey(key)
    engine.setPadding(slowDES.PAD_NORMAL)
    engine.setMode(slowDES.ECB)
    cb = engine.encrypt(codecs.decode(rec['PlainPINBlock_GJ'], 'hex'))
    rec.update(CipherPINBlock_GJ=str(codecs.encode(cb, 'hex')).upper())
    return rec


def test():
    print(generate_one(codecs.decode('11111111111111112222222222222222', 'hex')))
