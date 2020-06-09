#!/usr/bin/env python3
import asyncio
import struct
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash.HMAC import HMAC
import socket
import traceback
import io
import re
from config import *
import time
import gzip

loop = asyncio.get_event_loop()

random = Random.new()

req_session = random.read(8)
req_number_count = 0

async def client_handler(reader, writer):
    remote_reader, remote_writer = None, None
    try:
        from_addr, from_port = writer.get_extra_info('peername')
        ver = (await reader.readexactly(1))[0]
        if ver != 5:
            raise Excetion('unsupported')
        nmethods = (await reader.readexactly(1))[0]
        await reader.readexactly(nmethods)
        writer.write(b'\x05\x00')

        socksreq = await reader.readexactly(3)
        if socksreq != b'\x05\x01\x00':
            raise Exception('invalid socks5 req')
        atyp = (await reader.readexactly(1))[0]
        host = None
        if atyp == 1:
            hostbuf = await reader.readexactly(4)
            host = socket.inet_ntop(socket.AF_INET, hostbuf)
        elif atyp == 4:
            hostbuf = await reader.readexactly(16)
            host = socket.inet_ntop(socket.AF_INET6, hostbuf)
        elif atyp == 3:
            hostlen = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(hostlen)).decode()
        else:
            raise Exception('invalid socks5 req')
        port = struct.unpack('!H', await reader.readexactly(2))[0]
        writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        await writer.drain()
        print('Connecting [{}]:{}'.format(host, port))
        try:
            wait_req_task = asyncio.ensure_future(reader.read(65536), loop=loop)
            loop.call_later(0.1, wait_req_task.cancel)
            buf = None
            buf = await wait_req_task
        except asyncio.CancelledError as e:
            pass
        if buf != None:
            print('request:', buf[:20])
            if buf[:13] == b'POST /kcsapi/':
                await kancolle_client_handler(reader, writer, host, port, buf)
                return

        for conn_retry_count in range(3,-1,-1):
            try:
                remote_reader, remote_writer = await asyncio.open_connection(server_addr, server_port, loop=loop)
                break
            except:
                if conn_retry_count == 0:
                    print('Failed to connect to server, abort')
                    raise
                else:
                    print('Failed to connect to server, retry')
                    await asyncio.sleep(0.1)
    except:
        if remote_writer != None:
            remote_writer.close()
        writer.close()
        raise
    async def upload_loop(init_buf=None):
        nonlocal reader, remote_writer, host, port
        try:
            buf = init_buf
            iv_up = random.read(16)
            crypto_up = AES.new(enc_key, AES.MODE_CFB, iv_up)
            host = host.encode()
            req_buf = struct.pack('BB', 0, len(host)) + host + struct.pack('!H', port)
            mac = HMAC(mac_key, req_buf).digest()[:12]
            handshake_buf = iv_up + crypto_up.encrypt(req_buf + mac)
            while True:
                if buf == None:
                    buf = await reader.read(65536)
                if handshake_buf != None:
                    remote_writer.write(handshake_buf)
                    handshake_buf = None
                if len(buf) == 0:
                    break
                remote_writer.write(crypto_up.encrypt(buf))
                buf = None
                await remote_writer.drain()
        except ConnectionResetError as e:
            pass
        except Exception as e:
            print(e)
        finally:
            remote_writer.close()
    async def download_loop():
        nonlocal writer, remote_reader
        try:
            buf = None
            iv_down = await remote_reader.readexactly(16)
            crypto_down = AES.new(enc_key, AES.MODE_CFB, iv_down)
            while True:
                buf = crypto_down.decrypt(await remote_reader.read(65536))
                if len(buf) == 0:
                    break
                writer.write(buf)
                await writer.drain()
        except ConnectionResetError as e:
            pass
        except Exception as e:
            print(e)
        finally:
            writer.close()
    asyncio.ensure_future(upload_loop(buf), loop=loop)
    asyncio.ensure_future(download_loop(), loop=loop)

header_re = re.compile('^([0-9A-Za-z!#$%&\'*+-.^_`|~]+):\\s*(.*)\\s*$')
chunked_re = re.compile('^.*\\bchunked\s*$')
chunksize_re = re.compile('^([0-9a-fA-F]+)(;.*)?$')
async def http_message_parse_and_manipulate(reader, remain_buf):
    async def get_more():
        nonlocal reader, remain_buf
        tmpbuf = await reader.read(65536)
        if len(tmpbuf) == 0:
            raise Exception('unexpected EOF')
        remain_buf += tmpbuf
    headers = dict()
    content_length = None
    chunked = False
    modified = b''
    set_connection_close = False
    while remain_buf.find(b'\r\n\r\n') == -1:
        await get_more();
    for line in remain_buf.splitlines():
        if line == b'':
            break
        m = header_re.match(line.decode())
        if m == None: 
            modified += line + b'\r\n'
            continue
        mg = list(m.groups())
        if mg[0].lower() == 'connection':
            mg[1] = 'close'
            set_connection_close = True
        elif mg[0].lower() == 'transfer-encoding' and chunked_re.match(m[1]):
            chunked = True
        elif mg[0].lower() == 'content-length':
            content_length = int(mg[1])
        headers[mg[0]] = mg[1]
        modified += '{}: {}\r\n'.format(mg[0], mg[1]).encode()
    if not set_connection_close:
        modified += b'Connection: close\r\n'
    modified += b'\r\n'
    off = remain_buf.find(b'\r\n\r\n') + 4
    remain_buf = remain_buf[off:]
    if chunked:
        while True:
            while remain_buf.find(b'\r\n') == -1:
                await get_more()
            pos = remain_buf.find(b'\r\n')
            next_len = int(chunksize_re.match(remain_buf[:pos].decode()).group(1), 16)
            if next_len == 0:
                break
            modified += remain_buf[:pos+2]
            remain_buf = remain_buf[pos+2:]
            while len(remain_buf) < next_len + 2:
                get_more()
            modified += remain_buf[:next_len+2]
            remain_buf = remain_buf[next_len+2:]
    elif content_length != None:
        while len(remain_buf) < content_length:
            await get_more()
        modified += remain_buf[:content_length]
        remain_buf = remain_buf[content_length:]
    return modified, remain_buf

def manipulate_result(message):
    pos = message.find(b'\r\n\r\n')
    headers = message[:pos].split(b'\r\n')
    body = message[pos:]
    headers = [*filter(lambda h: not (h.strip()[:11].lower() == b'connection:'), headers)]
    headers.append(b'Connection: close')
    return b'\r\n'.join(headers) + body

def get_body(message):
    pos = message.find(b'\r\n\r\n')
    header_buf = message[:pos]
    body_buf = message[pos+4:]
    first_line = True
    gzipped = False
    content_length = None
    chunked = False
    for line in header_buf.splitlines():
        if first_line:
            first_line = False
        else:
            m = header_re.match(line.decode())
            mg = list(m.groups())
            if mg[0].lower() == 'transfer-encoding':
                if mg[1].find('chunked') != -1:
                    chunked = True
                if mg[1].find('gzip') != -1:
                    gzipped = True
            elif mg[0].lower() == 'content-length':
                content_length = int(mg[1])
            elif mg[0].lower() == 'content-encoding':
                if mg[1].find('gzip') != -1:
                    gzipped = True
    if chunked:
        remain_buf = body_buf
        body_buf = b''
        while len(remain_buf) > 0:
            pos = remain_buf.find(b'\r\n')
            if pos == -1:
                raise Exception('unexpected http message')
            next_len = int(chunksize_re.match(remain_buf[:pos].decode()).group(1), 16)
            if next_len == 0:
                break
            body_buf += remain_buf[pos+2:pos+2+next_len]
            remain_buf = remain_buf[pos+2+next_len+2:]
    if gzipped:
        try:
            body_buf = gzip.decompress(body_buf)
        except Exception as e:
            print('gunzip error, header is', body_buf[:10])
            print('error is', e)
            f = open('errfile', 'wb')
            f.write(body_buf)
            f.close()
    return body_buf

async def kancolle_client_handler(reader, writer, host, port, init_buf):
    global req_number_count
    async def do_request(req_counter):
        global req_session
        nonlocal req_number, host, port
        remote_reader, remote_writer = None, None
        try:
            iv_up = random.read(16)
            crypto_up = AES.new(enc_key, AES.MODE_CFB, iv_up)
            req_buf = struct.pack('BB', 1, len(host)) + host.encode() + struct.pack('!H', port)
            mac = HMAC(mac_key, req_buf).digest()[:12]
            handshake_buf = iv_up + crypto_up.encrypt(req_buf + mac)

            remote_reader, remote_writer = await asyncio.open_connection(server_addr, server_port, loop=loop)
            req_info = req_session + struct.pack('!QQI', req_number, req_counter, len(modified_req))
            remote_writer.write(handshake_buf + crypto_up.encrypt(req_info + modified_req))

            iv_down = await remote_reader.readexactly(16)
            crypto_down = AES.new(enc_key, AES.MODE_CFB, iv_down)
            result_len, = struct.unpack('!I', crypto_down.decrypt(await remote_reader.readexactly(4)))
            result = crypto_down.decrypt(await remote_reader.readexactly(result_len))
            remote_writer.close()
            return result
        except Exception:
            if remote_writer != None:
                remote_writer.close()
            raise
    try:
        modified_req, remain_buf = await http_message_parse_and_manipulate(reader, init_buf)
        print("Interfered request to {}:{} {}".format(host, port, modified_req[:modified_req.find(b'\r\n')].decode()))
        req_number = req_number_count
        req_number_count += 1

        result = None
        for req_counter in range(0,retry+1):
            try:
                if req_counter > 0:
                    print("Retry the {}-th time".format(req_counter))
                cur = time.perf_counter()
                req_task = asyncio.ensure_future(do_request(req_counter), loop=loop)
                loop.call_later(retry_timeout, req_task.cancel)
                result = await req_task
                break
            except asyncio.CancelledError as e:
                continue # retry
            except Exception as e:
                print(e)
                difftime = time.perf_counter() - cur
                if difftime < 10:
                    await asyncio.sleep(retry_timeout - difftime)
                continue
        if result == None:
            raise Exception('no response')
        print('result len:', len(result))
        result = manipulate_result(result)
        if True:
            try:
                print(get_body(result).decode()[:100])
            except Exception as e:
                print('get body error', e)
        writer.write(result)
        writer.close()
    except:
        writer.close()
        raise

coro = asyncio.start_server(client_handler, '0.0.0.0', client_port, loop=loop)
client = loop.run_until_complete(coro)

try:
    loop.run_forever()
except KeyboardInterrupt:
    pass

client.close()
loop.run_until_complete(client.wait_closed())
loop.close()
