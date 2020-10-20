#!/usr/bin/env python3
'''UFIBER NANO G Hack Tool'''
from sys import argv, exit as sexit
from os.path import exists
from struct import unpack
from argparse import ArgumentParser
from hashlib import sha256
from hashlib import md5
from binascii import hexlify, unhexlify
from getpass import getpass
from colorama import Fore
from paramiko import SSHClient, AutoAddPolicy
from paramiko.ssh_exception import AuthenticationException
from scp import SCPClient

RED = Fore.RED
GREEN = Fore.GREEN
BLUE = Fore.BLUE
RESET = Fore.RESET

local_crc32_table = [
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,
    0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
    0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
    0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
    0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE,
    0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC,
    0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
    0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
    0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
    0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940,
    0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116,
    0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
    0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
    0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
    0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A,
    0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818,
    0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
    0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C,
    0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2,
    0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
    0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
    0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
    0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086,
    0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4,
    0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
    0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
    0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
    0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,
    0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE,
    0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
    0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
    0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
    0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252,
    0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60,
    0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
    0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
    0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
    0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04,
    0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A,
    0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
    0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
    0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
    0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E,
    0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C,
    0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
    0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
    0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
    0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0,
    0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6,
    0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
    0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
    0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D,
]


def get_mtdblock3():
    '''Get mtdblock3 using SSH'''
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())

    try:
        ssh.connect('192.168.1.1', 22, 'ubnt',
                    getpass(prompt="SSH PASSWORD: "))
    except TimeoutError:
        print("[%sERROR%s] UFiber NANO G Unreachable" % (RED, RESET))
        sexit(0)
    except AuthenticationException:
        print("[%sERROR%s] Invalid SSH Password" % (RED, RESET))

    _, stdout, _ = ssh.exec_command('cat /dev/mtdblock3')
    return ssh, stdout.read()


def get_crc32(data, crc=0xffffffff):
    '''Generate new CRC32'''
    for i in data:
        crc = (crc >> 8) ^ local_crc32_table[(crc ^ i) & 0xff]
    return crc & 0xffffffff


def hex_format(data):
    '''Hex Format'''
    hex_bytes = b''
    for i in range(len(data)//2):
        if i != 0:
            hex_bytes += b':'
        hex_bytes += data[2*i:2*(i+1)]
    return hex_bytes


def get_mac(data):
    '''Mac2Hex'''
    data = hexlify(data)
    return hex_format(data)


def get_serial(sn_vendor_id, sn_serial_id):
    '''Serial2Hex'''
    data = hexlify(sn_vendor_id) + sn_serial_id
    return hex_format(data)


def check_vendor_id(data):
    '''Vendor id check'''
    for i in data:
        if not 65 <= i <= 90:
            return False
    return True


def nvram_info(mtdblock3):
    '''Get Infos from NVRAM'''
    nvram_block = mtdblock3[1408:1408+1024]
    nvram_version = unpack('!I', nvram_block[0:4])
    boot_line = nvram_block[4:260].decode()
    board_id = nvram_block[260:276].decode()
    main_thread = unpack('!I', nvram_block[276:280])
    psi_size = unpack('!I', nvram_block[280:284])
    num_mac_addr = unpack('!I', nvram_block[284:288])
    base_mac_addr = get_mac(nvram_block[288:294]).decode()
    old_check_sum = hex(int.from_bytes(nvram_block[296:300], byteorder='big'))
    gpon_sn_vendor_id = nvram_block[300:304].decode()
    gpon_sn_serial_id = nvram_block[304:313].decode()
    gpon_password = nvram_block[313:324].decode()
    checksum = hex(int.from_bytes(nvram_block[1020:1024], byteorder='big'))
    serial = get_serial(gpon_sn_vendor_id.encode(),
                        gpon_sn_serial_id.encode()).decode()

    print("[%sINFO%s] \n\
       nvram_version: %s \n\
       boot_line: %s \n\
       board_id: %s \n\
       main_thread: %s \n\
       psi_size: %s \n\
       num_mac_addr: %s \n\
       base_mac_addr: %s \n\
       vendor_id: %s \n\
       serial_id: %s \n\
       serial_formatted: %s \n\
       gpon_password: %s \n\
       old_check_sum: %s%s%s \n\
       checksum: %s%s%s" % (
        GREEN,
        RESET,
        nvram_version[0],
        boot_line,
        board_id,
        main_thread[0],
        psi_size[0],
        num_mac_addr[0],
        base_mac_addr,
        gpon_sn_vendor_id,
        gpon_sn_serial_id,
        serial,
        gpon_password,
        GREEN,
        old_check_sum,
        RESET,
        GREEN,
        checksum,
        RESET))

    return nvram_version, boot_line, board_id, main_thread, psi_size, \
        num_mac_addr, base_mac_addr, gpon_sn_vendor_id, gpon_sn_serial_id, \
        serial, \
        gpon_password, old_check_sum, checksum


def nvram_upgrade(mtdblock3, serial_number, mac_addr):
    '''NVRAM Upgrade'''
    nvram_block = mtdblock3[1408:1408+1024]
    length = len(serial_number)

    if length != 12:
        print("[%sERROR%s] Invalid serial number length" % (RED, RESET))
        sexit(0)

    gpon_sn_vendor_id = serial_number[0:4].encode()
    gpon_sn_serial_id = serial_number[4:].encode() + b'\x00'

    print("[%sINFO%s] New Serial Number: %s%s%s" % (GREEN,
                                                    RESET,
                                                    BLUE,
                                                    (gpon_sn_vendor_id +
                                                        gpon_sn_serial_id)
                                                    .decode(),
                                                    RESET))

    if not check_vendor_id(gpon_sn_vendor_id):
        print('[%sERROR%s] Invalid vendor_id' % (RED, RESET))
        sexit(0)

    nulls = b'\x00\x00\x00\x00'

    if mac_addr:
        mac_addr_new = mac_addr.replace(':', '').upper()
        mac_length = len(mac_addr_new)
        if mac_length != 12:
            print('[%sERROR%s] Invalid mac address length' % (RED, RESET))
            sexit(0)
        hex_mac_addr = unhexlify(mac_addr_new)
        print("[%sINFO%s] New Mac Address: %s%s%s" % (GREEN, RESET, BLUE,
                                                      mac_addr, RESET))
        nvram_block_new = nvram_block[:288] + hex_mac_addr + \
            nvram_block[294:300] + gpon_sn_vendor_id + gpon_sn_serial_id + \
            nvram_block[313:-4] + nulls
    else:
        nvram_block_new = nvram_block[:300] + gpon_sn_vendor_id + \
            gpon_sn_serial_id + nvram_block[313:-4] + nulls
    checksum = get_crc32(nvram_block_new).to_bytes(4, byteorder='big')

    print('[%sINFO%s] New Checksum: %s%s%s' % (GREEN, RESET,
                                               BLUE,
                                               hex(
                                                   int.from_bytes(
                                                        checksum,
                                                        byteorder="big"
                                                       )),
                                               RESET))

    nvram_block_new = nvram_block_new[:-4] + checksum
    mtdblock3_new = mtdblock3[:1408] + nvram_block_new + mtdblock3[1408+1024:]

    return mtdblock3_new


def hack(serial, mac_addr, file_mode):
    '''Main Function'''
    if file_mode and not exists('mtdblock3.bin'):
        print('[%sERROR%s] File not found' % (RED, RESET))
        sexit(0)
    elif file_mode:
        with open('mtdblock3.bin', 'rb') as file_stream:
            mtdblock3 = file_stream.read()
    else:
        ssh, mtdblock3 = get_mtdblock3()

    hashsum = sha256()
    hashsum.update(mtdblock3)

    print('[%sINFO%s] Hashsum of mtdblock3.bin (sha256): %s' % (GREEN, RESET,
                                                                hashsum.
                                                                hexdigest()))

    _, _, board_id, _, _, _, _, _, _,  _, _, _, _ = nvram_info(mtdblock3)

    if board_id != 'UBNT_SFU\x00\x00\x00\x00\x00\x00\x00\x00':
        print('[%sERROR%s] Your board_id is %s.' % (RED, RESET, board_id))
        sexit(0)

    mtdblock3_new = nvram_upgrade(mtdblock3, serial, mac_addr)
    mtdblock_new_file_name = serial + '.bin'

    if len(mtdblock3) != len(mtdblock3_new):
        print('[%sERROR%s] Invalid Binary Length' % (RED, RESET))

    hashsum = sha256()
    hashsum.update(mtdblock3_new)

    print("[%sINFO%s] Built %s\n \
      Hashsum of %s (sha256): %s" % (GREEN, RESET,
                                     mtdblock_new_file_name,
                                     mtdblock_new_file_name,
                                     hashsum.hexdigest()))

    with open(mtdblock_new_file_name, 'wb') as file_stream:
        file_stream.write(mtdblock3_new)

    _, _, _, _, _, _, _, _, _, _, _, _, _ = nvram_info(mtdblock3_new)

    if not file_mode:
        hashsum = md5()
        hashsum.update(mtdblock3_new)
        with SCPClient(ssh.get_transport()) as scp:
            scp.put(mtdblock_new_file_name, '/tmp/mtdblock3.bin')
        _, stdout, _ = ssh.exec_command(
                "md5sum /tmp/mtdblock3.bin | awk '{ print $1 }'")
        if stdout.read().decode().strip() == hashsum.hexdigest():
            _, _, _ = ssh.exec_command(
                "dd if=/tmp/mtdblock3.bin of=/dev/mtdblock3")
            print("[%sINFO%s] Remote Hashsum Match" % (GREEN, RESET))
            _, _, _ = ssh.exec_command(
                "/sbin/reboot")
            print("[%sINFO%s] Device Reboot" % (GREEN, RESET))
        else:
            _, _, _ = ssh.exec_command("rm /tmp/mtdblock3.bin")
            print("[%sERROR%s] Remote Hashsum Doesn't Match" % (RED, RESET))
    sexit(0)


if __name__ == '__main__':
    print("""%s    __  _______ __
   / / / / __(_) /  ___ ____
  / /_/ / _// / _ \\/ -_) __/
  \\____/_/ /_/_.__/\\__/_/    %s %sNANO G%s Hacking Tool
  """ % (GREEN, RESET, RED, RESET))
    USAGE = """
{0} -sn {1}ABCABCABCABC{2}
{0} -m {1}11:22:33:44:55:66{2}
{0} -m {1}11:22:33:44:55:66{2} -sn {1}ABCABCABCABC{2}
{0} -m {1}11:22:33:44:55:66{2} -sn {1}ABCABCABCABC{2} --file""".format(
                                                                       argv[0],
                                                                       GREEN,
                                                                       RESET)
    parser = ArgumentParser(usage=USAGE)

    if len(argv) < 2:
        parser.print_usage()
        sexit(1)

    parser.add_argument('-sn', '--serial', dest='serial', type=str,
                        default=None, required=True, help="Serial Number")
    parser.add_argument('-m', '--mac', dest='mac', type=str,
                        default=None, help="Mac Address")
    parser.add_argument('-f', '--file', action="store_true", help="File Mode")
    parser.add_argument('-dwonly', '--download-only', action="store_true",
                        help="mtdblock3 Download")
    args = parser.parse_args()

    if args.download_only:
        _, mtd = get_mtdblock3()
        print("[%sINFO%s] File Size: %s bytes" % (
            GREEN, RESET, len(mtd)))
        with open('mtdblock3.bin', 'wb') as mtd_stream:
            mtd_stream.write(mtd)
            sexit(0)

    if args.serial or args.mac:
        hack(args.serial, args.mac, args.file)
