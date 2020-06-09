#!/usr/bin/env python3
import asyncio
import struct
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash.HMAC import HMAC
import re
from config import *

loop = asyncio.get_event_loop()

random = Random.new()

async def server_handler(reader, writer):
    remote_reader, remote_writer = None, None
    try:
        from_addr, from_port = writer.get_extra_info('peername')
        print("Connection from [{}]:{}".format(from_addr, from_port))
        iv_up = await reader.readexactly(16)
        crypto_up = AES.new(enc_key, AES.MODE_CFB, iv_up)
        buf = b''
        buf += crypto_up.decrypt(await reader.readexactly(1))
        interfered = buf[-1]
        buf += crypto_up.decrypt(await reader.readexactly(1))
        hostlen = buf[-1]
        buf += crypto_up.decrypt(await reader.readexactly(hostlen))
        host = buf[-hostlen:].decode(errors='ignore')
        buf += crypto_up.decrypt(await reader.readexactly(2))
        port, = struct.unpack('!H', buf[-2:])
        mac_recv = crypto_up.decrypt(await reader.readexactly(12))
        mac = HMAC(mac_key, buf).digest()[:12]
        if mac_recv != mac:
            raise Exception('wrong mac')
        if interfered == 1:
            await kancolle_server_handler(reader, writer, host, port, crypto_up)
            return
        elif interfered != 0:
            raise Exception('unsupported')
        print('Connecting [{}]:{}'.format(host, port))
        remote_reader, remote_writer = await asyncio.open_connection(host, port, loop=loop)
        del buf
    except:
        if remote_writer != None:
            remote_writer.close()
        writer.close()
        raise
    async def upload_loop():
        nonlocal reader, remote_writer, crypto_up
        buf = None
        try:
            while True:
                buf = crypto_up.decrypt(await reader.read(65536))
                if len(buf) == 0:
                    break
                remote_writer.write(buf)
                await remote_writer.drain()
        except ConnectionResetError as e:
            pass
        except Exception as e:
            print(e)
        finally:
            remote_writer.close()
    async def download_loop():
        nonlocal writer, remote_reader
        buf = None
        crypto_down = None
        try:
            while True:
                buf = await remote_reader.read(65536)
                if crypto_down == None:
                    iv_down = random.read(16)
                    crypto_down = AES.new(enc_key, AES.MODE_CFB, iv_down)
                    writer.write(iv_down)
                if len(buf) == 0:
                    break
                writer.write(crypto_down.encrypt(buf))
                await writer.drain()
        except ConnectionResetError as e:
            pass
        except Exception as e:
            print(e)
        finally:
            writer.close()
    asyncio.ensure_future(upload_loop(), loop=loop)
    asyncio.ensure_future(download_loop(), loop=loop)


header_re = re.compile('^([0-9A-Za-z!#$%&\'*+-.^_`|~]+):\\s*(.*)\\s*$')
chunked_re = re.compile('^.*\\bchunked\s*$')
chunksize_re = re.compile('^([0-9a-fA-F]+)(;.*)?$')
async def http_message_parse_and_manipulate(reader, remain_buf):
    async def get_more():
        raise Exception('invalid http message')
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
            next_len = int(chunksize_re.match(main_buf[:pos].decode()).group(1), 16)
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

req_tasks = {}
req_session_max_num = {}
async def kancolle_server_handler(reader, writer, host, port, crypto_up):
    async def do_request(host, port, req_content):
        print("Making interfered request to {}:{}".format(host, port))
        retry_times = 5
        while retry_times > 0:
            try:
                fut = asyncio.open_connection(host, port, loop=loop)
                remote_reader, remote_writer = await asyncio.wait_for(fut, timeout=3)
                break
            except:
                retry_times -= 1
        if retry_times <= 0:
            raise Exception('connection fail')
        try:
            remote_writer.write(req_content)
            result = b''
            while True:
                buf = await remote_reader.read()
                result += buf
                if len(buf) == 0:
                    break
            remote_writer.close()
            return result
        except:
            remote_writer.close()
            raise

    def remove_task(taskkey):
        del req_tasks[taskkey]

    try:
        req_info = crypto_up.decrypt(await reader.readexactly(28))
        req_session, req_number, req_counter, req_len = struct.unpack('!QQQI', req_info)
        req_content = crypto_up.decrypt(await reader.readexactly(req_len))
        req_content, remain_buf = await http_message_parse_and_manipulate(None, req_content)

        print("Request to {}:{} session {} number {} count {} http {}".format(host, port, req_session, req_number, req_counter, req_content[:req_content.find(b'\r\n')].decode()))
        taskkey = req_session * 2**64 + req_number
        if req_session not in req_session_max_num:
            req_session_max_num[req_session] = req_number
        elif req_number < req_session_max_num[req_session] and taskkey not in req_tasks:
            writer.close()
            raise Exception('req out of order!')
        if taskkey not in req_tasks:
            req_tasks[taskkey] = asyncio.ensure_future(do_request(host, port, req_content), loop=loop)
            loop.call_later((retry + 1) * retry_timeout * 1.5 + 30, remove_task, taskkey)
        result = await req_tasks[taskkey]
        print("Sending response")
        iv_down = random.read(16)
        crypto_down = AES.new(enc_key, AES.MODE_CFB, iv_down)
        writer.write(iv_down)
        writer.write(crypto_down.encrypt(struct.pack('!I', len(result))))
        writer.write(crypto_down.encrypt(result))
        writer.close()
    except:
        writer.close()
        raise


coro = asyncio.start_server(server_handler, '0.0.0.0', server_port, loop=loop)
server = loop.run_until_complete(coro)

try:
    loop.run_forever()
except KeyboardInterrupt:
    pass

server.close()
loop.run_until_complete(server.wait_closed())
loop.close()