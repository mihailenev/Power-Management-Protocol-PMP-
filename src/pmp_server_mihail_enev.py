import json # Working with JSON data
import pyDH # Pure Python Implementation of Diffie-Hellman Key Exchange
import time # Provides various time-related functions
import base64 # For encoding binary data to printable ASCII characters and decoding such encodings back to binary data
import psutil # For retrieving information on running processes and system utilization
import socket # Access to the BSD socket interface
import string # Common string operations
import random # Generate pseudo-random numbers
import hashlib # Interface for many different secure hash and message digest algorithms
import binascii # Used for ASCII-encoded binary representations
from threading import Thread # higher-level threading interfaces
from Crypto.Cipher import AES, PKCS1_OAEP # Advanced Encryption Standard and public-key encryption scheme combining for RSA(PKCS1_OAEP)
from Crypto.PublicKey import RSA # Rivest–Shamir–Adleman(public key algorithm)
from Crypto.Util.Padding import pad, unpad # For adding and removing standard padding from data
from Crypto.Random import get_random_bytes # Return a random byte string of length N


CONN_STATES = {}
INACTIVE_TIMEOUT = 120 # If a connection does not send a packet for 120 seconds, its state is wiped
BLOCK_SIZE = 16
SUSPENDING = False
SUSPEND_TIME = 10
BUFFER_SIZE = 4096
PKT_FLAGS = ['SYN', 'RES', 'CRP', 'AUTH']
COMMANDS = ['PWR_STAT', 'BTRY_LVL', 'SUSPEND', 'REBOOT', 'PWROFF', 'END_CONN'] # Available commands

# Converting the input provided by the client
def convertInput():
    config = {}
    config['local_addr'] = input('Server IP: ')
    config['config_file'] = input('Configuration file: ')
    return config

# Encrypting using RSA public key
def encryptRSA(plainText, keyFile):
    rsaPublicKey = RSA.importKey(open(keyFile).read())
    rsaPublicKey = PKCS1_OAEP.new(rsaPublicKey)
    return rsaPublicKey.encrypt(plainText)

# Decrypting using RSA private key
def decryptRSA(cipherText, keyFile):
    rsaPrivateKey = RSA.importKey(open(keyFile).read())
    rsaPrivateKey = PKCS1_OAEP.new(rsaPrivateKey)
    return rsaPrivateKey.decrypt(cipherText)


# Encrypting AES
def encryptAES(plainText, key):
    cipher = AES.new(key, AES.MODE_CBC)
    # adding 16 byte Initialization Vector
    return cipher.encrypt(pad(plainText, BLOCK_SIZE)) + cipher.iv

# Decrypting AES
def decryptAES(cipherText, key):
    try:
        iv = cipherText[-16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        # adding 16 byte Initialization Vector
        return unpad(cipher.decrypt(cipherText[:-16]), BLOCK_SIZE)
    except (ValueError, KeyError):
        print('Incorrect decryption!')
        exit()

# Printing the packet
def printPacket(flags, seq, data, key):
    if key != None and not flags['SYN']: data = decryptAES(data, key)
    print(f'Packet: {data}')
    return

# Building a packet
#setting headers and data
#calculateing and adding checksum(CRC32)
def buildPacket(flags, sequenceNum, data, key=None):
    if sequenceNum > 4094:
        print('Maximum number of packets per connection sent.')
        exit()
    header = 0
    for i in range(len(PKT_FLAGS)):
        # Bitwise left shift to align packet flags
        header = header + (flags[PKT_FLAGS[i]] << 15-i)
    header = header + sequenceNum
    # Geting theh header in hexadecimal
    hexHeader = format(header, '04x')
    # Geting theh header in bytes
    header = bytes.fromhex(hexHeader)
    if key != None: data = encryptAES(data, key)
    packet = header + data
    # Calculating the checksum of the packet
    checksum = binascii.crc32(packet).to_bytes(4, byteorder='big')
    # Adding the checksum to the packet
    packet = checksum + packet
    return packet

# Sending server response to the client
def serverResponse(server, flags, sequenceNum, payload, address, key=None):
    flags['RES'] = True

    payload = json.dumps(payload).encode()
    if key != None:
        payload = encryptAES(payload, key)
    packet = buildPacket(flags, sequenceNum, payload)
    server.sendto(packet, address)
    return

# Whenever a new connection state is saved, a deletion thread is spawned
# The thread decrements the connection TTL each second until it reaches 0,
# at which point the state is wiped. TTL is reset upon receival of new
# packets from a connection
def deletionThread(address, port):
    global CONN_STATES
    # Thread module does not like passing tuples as function arguments
    address = (address, port)
    while True:
        time.sleep(1)
        if CONN_STATES[address]['TTL'] <= 0:
            print(f'TIMEOUT: Connection is closed {address[0]}')
            CONN_STATES.pop(address)
            return
        CONN_STATES[address]['TTL'] -= 1

# Setting the TTL of the address to 0
def endConn(address):
    global CONN_STATES
    CONN_STATES[address]['TTL'] = 0
    return

# Creating new conn status or updating the TTL of the address
def updateConnStatus(address):
    global CONN_STATES
    if address in CONN_STATES:
        # Handle when deletion thread gets rid of conn
        try:
            CONN_STATES[address]['TTL'] = INACTIVE_TIMEOUT
            return
        except KeyError:
            updateConnStatus(address)
            return
    CONN_STATES[address] = {'key': None, 'authenticated': False, 'TTL': INACTIVE_TIMEOUT}
    Thread(target=deletionThread, args=(address)).start()
    return

# Running the commands
def cmdCommands(command):
    battery = psutil.sensors_battery()
    # Battery commands
    if command == 'PWR_STAT':
        return 'PLUGGED IN' if battery.power_plugged else 'NOT PLUGGED IN'
    elif command == 'BTRY_LVL':
        return str(f'{battery.percent}%')
    return '  *SUSPEND, REBOOT and PWROFF are not available for now'

# Diffie-Hellman key exchange
def keyЕxchange(server, receivedFlags, recv_seq, parsedJson, address):
    global CONN_STATES
    # Processing response
    if ('modp_id' not in parsedJson) or ('pub_key' not in parsedJson):
        print('Client has not sent MODP_ID or PUBLIC_KEY for Diffie-Hellman key exchange')
        return
    serverPublicKey = pyDH.DiffieHellman(parsedJson['modp_id'])
    payload = {'pub_key': serverPublicKey.gen_public_key()}
    serverResponse(server, receivedFlags, recv_seq+1, payload, address)
    # Calculating and store encryption key for connection
    sharedSecret = serverPublicKey.gen_shared_key(parsedJson['pub_key'])
    CONN_STATES[address]['key'] = hashlib.sha256(sharedSecret.encode('utf-8')).digest()
    return

# Handle authentication requests from a client
def authenticationSequence(server, receivedFlags, receivedSequence, parsedJson, address, config_file):
    global CONN_STATES

    key = CONN_STATES[address]['key']
    # Check initial authentication request
    if 'auth' in parsedJson:
        if parsedJson['auth'] not in config_file:
            print('Provided user is not in config file')
            serverResponse(server, receivedFlags, receivedSequence+1, {'err': 'BAD_USER'}, address, key)
        
        # Cryptographically secure 64 byte hexadecimal generator
        challenge = ''.join(random.SystemRandom().choice(string.hexdigits) for _ in range(64)).encode()
        CONN_STATES[address]['username'] = parsedJson['auth']
        CONN_STATES[address]['auth_chal'] = base64.b64encode(challenge).decode()

        serverResponse(server, receivedFlags, receivedSequence+1, {'auth_chal': base64.b64encode(encryptRSA(challenge, config_file[parsedJson['auth']])).decode()}, address, key)
        return
    # Check authentication solution response
    elif 'auth_solution' in parsedJson:
        if 'auth_chal' not in CONN_STATES[address]:
            print('Provided auth solution but challenge was not issued')
            serverResponse(server, receivedFlags, receivedSequence+1, {'err': 'BAD_AUTH'}, address, key)
            return

        if parsedJson['auth_solution'] != CONN_STATES[address]['auth_chal']:
            print('Client did not solve authentication challenge')
            serverResponse(server, receivedFlags, receivedSequence+1, {'err': 'BAD_AUTH'}, address, key)
            return

        CONN_STATES[address]['authenticated'] = True
        serverResponse(server, receivedFlags, receivedSequence+1, {'ok': 'AUTHENTICATED'}, address, key)
        return

    print('Not provide username or authentication challenge solution')
    serverResponse(server, receivedFlags, receivedSequence+1, {'err': 'BAD_AUTH'}, address, key)
    return

# Performming commands
def cmdSequence(server, receivedFlags, receivedSequence, parsedJson, address):
    key = CONN_STATES[address]['key']
    if 'cmd' not in parsedJson:
        print('Not provide command')
        serverResponse(server, receivedFlags, receivedSequence+1, {'err': 'BAD_CMD'}, address, key)
        return
    elif not parsedJson['cmd'] in COMMANDS:
        print('Provided an invalid command')
        serverResponse(server, receivedFlags, receivedSequence+1, {'err': 'BAD_CMD'}, address, key)
        return
    elif parsedJson['cmd'] == 'END_CONN':
        serverResponse(server, receivedFlags, receivedSequence+1, {'ok': 'CONNECTION CLOSED'}, address, key)
        endConn(address)
        return
    serverResponse(server, receivedFlags, receivedSequence+1, {'ok': cmdCommands( parsedJson['cmd'])}, address, key)
    return

# Verifing and unpack the received packet
def verifyAndUnpack(rawPacket):
    if len(rawPacket) < 7:
        print(f'Packet too small ', end='\r')
        return (None, None, None)
    # Adding checksum
    receivedChecksum = rawPacket[:4]
    performedChecksum = binascii.crc32(rawPacket[4:]).to_bytes(4, byteorder='big')

    # Adding 2 more bytes at offset and convert to binary
    header = format(int.from_bytes(rawPacket[4:6], byteorder='big'), '016b')
    # Received sequence number
    recvSeq = int(header[4:], 2)
    if performedChecksum != receivedChecksum: return (None, recvSeq, None)
    # Flags are the first 4 bits
    recvFlagsStr = header[:4]
    recvFlags = {}
    for i in range(len(PKT_FLAGS)): recvFlags[PKT_FLAGS[i]] = bool(int(recvFlagsStr[i]))
    return (recvFlags, recvSeq, rawPacket[6:])

# Handelling the packet depends on the action
def handlePacket(server, packet, address, config_file):
    # Updating connection status
    updateConnStatus(address)
    # Unpacking received packet
    unpacked = verifyAndUnpack(packet)
    key = CONN_STATES[address]['key']
    if None in unpacked:
        if receivedSequence != None:
            # If the packet sequence number is not corrupted, reply with CRP packet
            flags = {'SYN': False, 'RES': False, 'CRP': True, 'AUTH': False}
            print('[!] Corrupted packet')
            serverResponse(server, receivedFlags, receivedSequence+1, {'err': 'BAD_PACKET'}, address, key)
        return
    (receivedFlags, receivedSequence, unpacked) = unpacked
    printPacket(receivedFlags, receivedSequence, unpacked, key)

    try:
        # Handle invalid packets
        if receivedFlags['CRP']:
            print('Client should retransmit packet')
            serverResponse(server, receivedFlags, receivedSequence+1, {'err': 'BAD_PACKET'}, address, key)
            return
        elif (receivedFlags['SYN'] and receivedFlags['AUTH']) or receivedFlags['RES']:
            print('Client sent invalid packet')
            serverResponse(server, receivedFlags, receivedSequence+1, {'err': 'BAD_PACKET'}, address, key)
            return
        # Perform Diffie-Hellman key exchange
        elif receivedFlags['SYN']:
            keyЕxchange(server, receivedFlags, receivedSequence, json.loads(unpacked), address)
            return
        elif key == None:
            print('Client attempted to authenticate before establishing a connection')
            serverResponse(server, receivedFlags, receivedSequence+1, {'err': 'NOT_SYNCED'}, address)
            return
        # Perform authentication
        elif receivedFlags['AUTH']:
            authenticationSequence(server, receivedFlags, receivedSequence, json.loads(decryptAES(unpacked, key)), address, config_file)
            return
        elif not CONN_STATES[address]['authenticated']:
            print('Client did not provide username or authentication challenge solution')
            serverResponse(server, receivedFlags, receivedSequence+1, {'err': 'BAD_PERM'}, address, key)
            return
        cmdSequence(server, receivedFlags, receivedSequence, json.loads(decryptAES(unpacked, key)), address)
        return
    except EOFError as e:
        print('Client sent invalid JSON')
        serverResponse(server, receivedFlags, receivedSequence+1, {'err': 'BAD_PACKET'}, address, key)
        return

# Receive datagram and send off for processing
def listenLoop(server, config_file):
    while True:
        packet, address = server.recvfrom(BUFFER_SIZE)
        handlePacket(server, packet, address, config_file)

def main():
    config = convertInput()

    try:
        config_file = json.loads(open(config['config_file']).read()) # Load config
    except (UnicodeDecodeError, json.decoder.JSONDecodeError) as e:
        print('Not valid JSON')
        exit(1)
    # Create and bind socket
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((config['local_addr'], 2525))
    print(f'Server listening on {config["local_addr"]}:2525')
    listenLoop(server, config_file)

main()