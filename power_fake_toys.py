#!/usr/bin/env python
# -*- coding: utf-8 -*-

import codecs
import random
import re
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


def generate_psn():
    return generate_num(2)


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


def get_pan_16_from_pan_psn(pan, psn):
    if len(pan) < 16:
        pan = '0' * (16 - len(pan)) + pan
    if len(psn) < 2:
        psn = '0' * (2 - len(psn)) + psn
    assert len(pan) >= 16, "pan too short"
    assert len(psn) == 2, "psn too long"
    return (pan + psn)[-16:]


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


def extract_numer(b):
    # type: (bytes)->str
    str_buf = codecs.encode(b, 'hex').decode("ascii")
    n_buf = []
    h_buf = []
    for c in str_buf:
        if c.isdigit():
            n_buf.append(c)
        else:
            h_buf.append(c)
    for c in h_buf:
        n_buf.append("%d" % (int(c, 16) % 10))
    return ''.join(n_buf)


def generate_mst(key=None):
    # type: ([str])->object
    """
    生成一条数据记录
    :param key: 加密密钥
    :return: 产生的随机记录
    """
    rec = {}
    rec.update(PAN=generate_pan())
    rec.update(PSN=generate_psn())
    rec.update(ATC=generate_num(3))
    rec.update(VER='1')
    rec.update(TIMESTAMP=generate_num(16))
    rec.update(EXPIRETIME=generate_num(4))

    if len(key) == 16:
        engine = triple_des(key)
    else:
        raise ValueError("Invalid Key")

    udk_engine = calc_card_udk_pboc_2(engine, rec.get("PAN"), rec.get("PSN"))
    session_key = calc_mst_session_key(udk_engine, rec.get("ATC"), rec.get("TIMESTAMP"))
    buf = []
    # CC CV TT TT TT TT TT TT TT TT YY YY MM MM
    buf.append(rec.get("ATC"))
    buf.append(rec.get("VER"))
    buf.append(rec.get("TIMESTAMP"))
    buf.append(codecs.encode(bytes(rec.get("EXPIRETIME"), 'ascii'), 'hex').decode("ascii"))

    data = codecs.decode(''.join(buf).encode('ascii'), 'hex')
    des_engine_1 = des(session_key[:8], mode=slowDES.CBC, IV='\x00' * 8, pad='\x00', padmode=slowDES.PAD_NORMAL)
    des_engine_1.setMode(slowDES.CBC)
    des_engine_1.setPadding("\x00")
    des_engine_1.setPadMode(slowDES.PAD_NORMAL)
    des_engine_1.setIV('\x00' * 8)

    des_engine_2 = des(session_key[8:])
    des_engine_3 = des(session_key[:8])

    block = des_engine_1.encrypt(data)
    # print(codecs.encode(block, 'hex'))
    block = block[-8:]
    # print(codecs.encode(block, 'hex'))
    block = des_engine_2.decrypt(block)
    # print(codecs.encode(block, 'hex'))
    out = des_engine_3.encrypt(block)
    # print(codecs.encode(out, 'hex'))
    rec.update(MST=extract_numer(out)[:6])
    return rec


def reverse_data_bits(data):
    # type: (bytes)->bytes
    arr_buf = []
    for i in data:
        arr_buf.append(i ^ 0xff)
    return bytes(arr_buf)


def calc_card_udk_pboc_2(engine, pan, psn):
    spn = get_pan_16_from_pan_psn(pan, psn)
    block = codecs.decode(spn, 'hex')
    assert len(block) == 8
    l_key = engine.encrypt(block)
    r_key = engine.encrypt(reverse_data_bits(block))
    return triple_des(l_key + r_key)


N16 = re.compile("[0-9]{16}")
N03 = re.compile("[0-9]{3}")


def calc_mst_session_key(engine, atc, time):
    # type: (triple_des,[str],[str])->object
    assert N16.match(time) is not None, "time is 16 n"
    assert N03.match(atc) is not None, "atc is 3 n"
    buf = []
    for i in atc:
        buf.append("0")
        buf.append(i)
    buf.append(time[6:])
    left = codecs.decode(''.join(buf).encode('ascii'), 'hex')
    right = reverse_data_bits(left)
    l_data = engine.encrypt(left)
    r_data = engine.encrypt(right)
    return l_data + r_data


def test():
    print(generate_one(codecs.decode(b'11111111111111112222222222222222', 'hex')))


def test_mst():
    print(generate_mst(codecs.decode(b"10101010232323233232323245454545", 'hex')))
