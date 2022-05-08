import json # Working with JSON data
import pyDH # Pure Python Implementation of Diffie-Hellman Key Exchange
import base64 # For encoding binary data to printable ASCII characters and decoding such encodings back to binary data
import socket # Access to the BSD socket interface
import hashlib # Interface for many different secure hash and message digest algorithms
import binascii # Used for ASCII-encoded binary representations
from Crypto.Cipher import AES, PKCS1_OAEP # Advanced Encryption Standard and public-key encryption scheme combining for RSA(PKCS1_OAEP)
from Crypto.PublicKey import RSA # Rivest–Shamir–Adleman(public key algorithm)
from Crypto.Util.Padding import pad, unpad # For adding and removing standard padding from data
from Crypto.Random import get_random_bytes # Return a random byte string of length N

BLOCK_SIZE = 16
PKT_NUMBER = 0 # Global variable for packet numbering
PKT_FLAGS = ['SYN', 'RES', 'CRP', 'AUTH']
RETRY_LIMIT = 25 # If a response to a packet is not received after 25 attempts, server is unreachable
BUFFER_SIZE = 4096
TIMEOUT_LIMIT = 10 # If 10 subsequent timeouts occur, SERVER is considered unreachable
CURRENT_TIMEOUTS = TIMEOUT_LIMIT
TIMEOUT = 2 # Packet timeout in seconds
COMMANDS = ['PWR_STAT', 'BTRY_LVL', 'SUSPEND', 'REBOOT', 'PWROFF', 'END_CONN'] # Available commands

# Converting the input provided by the client
def convertInput():
    config = {}
    config['local_addr'] = input('Client IP address: ')
    config['rsa_file'] = input('Identity file: ')
    config['user'] = input('Username: ')
    config['server_ip'] = input('Server IP: ')
    config['server_port'] = int(input('Server port: '))
    return config

# Auto-increment the packet sequence number by 2
def getAndIncrementPacet():
    global PKT_NUMBER
    currentSequence = PKT_NUMBER
    PKT_NUMBER += 2
    return currentSequence

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

# Validating the packet flags and sequence number
def headersValidation(sentFlags, sentSeq, recvFlags, recvSeq):
    if recvFlags['CRP']:
        return False
    elif not recvFlags['RES']:
        print('R ES flag is not set')
        return False
    elif (sentFlags['SYN'] != recvFlags['SYN']) or (sentFlags['AUTH'] != recvFlags['AUTH']):
        print('SYN or AUTH not matching')
        return False
    # The response sequence number should be + 1
    elif sentSeq+1 != recvSeq:
        print('Sequence does not match')
        return False
    return True

# Sends and returns a packet through specified socket
def sendAndReceivePacket(sentFlags, sentSeq, client, packet, address):
    global CURRENT_TIMEOUTS
    for _ in range(RETRY_LIMIT):
        try:
            client.settimeout(TIMEOUT)
            client.sendto(packet, address)
            # Check the received packet address
            while True:
                (rawPacket, addr) = client.recvfrom(BUFFER_SIZE)
                if addr == address:
                    break
            # Reseting timeouts
            CURRENT_TIMEOUTS = TIMEOUT_LIMIT
            unpacked = verifyAndUnpack(rawPacket)
            if None in unpacked:
                continue
            (recvFlags, recvSeq, unpacked) = unpacked
            if headersValidation(sentFlags, sentSeq, recvFlags, recvSeq):
                return unpacked
        except socket.timeout:
            if CURRENT_TIMEOUTS <= 0:
                print(f'Unreachable host {address[0]}:{address[0]}')
                exit()
            else:
                CURRENT_TIMEOUTS -= 1
    print(f'Unreachable host {address[0]}:{address[0]}')
    exit()

# Diffie-Hellman key exchange
def diffieHellman(client, address):
    # Creating a packet
    sentFlags = {'SYN': True, 'RES': False, 'CRP': False, 'AUTH': False}
    sequenceNum = getAndIncrementPacet()
    clientPublicKey = pyDH.DiffieHellman(14)
    sentData = {'modp_id': 14, 'pub_key': clientPublicKey.gen_public_key()}
    # Encode dictionary to JSON as bytes
    payload = json.dumps(sentData).encode()
    packet = buildPacket(sentFlags, sequenceNum, payload)
    
    # Processing response
    receivedData = json.loads(sendAndReceivePacket(sentFlags, sequenceNum, client, packet, address))
    if 'pub_key' not in receivedData:
        print('Not a public key in the server response')
        exit()
    shared_secret = clientPublicKey.gen_shared_key(receivedData['pub_key'])
    return shared_secret.encode('utf-8')

# Return True for error and False for not
def errorsHandler(recvPacket):
    if 'err' in recvPacket:
        error = recvPacket['err']
        print(f'Error received: {error}')
        if error == 'BAD_USER' or error == 'BAD_AUTH' or error == 'NOT_SYNCED':
            exit()
        return True
    return False

# Handling Server authentication challenge
def authenticate(config, client, key):
    sentFlags = {'SYN': False, 'RES': False, 'CRP': False, 'AUTH': True}
    sequenceNum = getAndIncrementPacet()
    sentData = {'auth': config["user"]}
    payload = json.dumps(sentData).encode()
    packet = buildPacket(sentFlags, sequenceNum, payload, key)

    # Processing authentication challenge
    receivedData = json.loads(decryptAES(sendAndReceivePacket(sentFlags, sequenceNum, client, packet, (config['server_ip'], config['server_port'])), key))
    if errorsHandler(receivedData):
        print(f'Error in authentication sequence {receivedData["err"]}')
        exit()
    elif not 'auth_chal' in receivedData:
        print('Not an authentication challenge in the server response')
        exit()
    
    sequenceNum = getAndIncrementPacet()
    decrypted = decryptRSA(base64.b64decode(receivedData['auth_chal']), config['rsa_file'])
    chalResponse = {'auth_solution': base64.b64encode(decrypted).decode()}
    payload = json.dumps(chalResponse).encode()
    packet = buildPacket(sentFlags, sequenceNum, payload, key)

    # Processing authentication challenge
    receivedData = json.loads(decryptAES(sendAndReceivePacket(sentFlags, sequenceNum, client, packet, (config['server_ip'], config['server_port'])), key))
    if errorsHandler(receivedData):
        print(f'Error in authentication sequence {receivedData["err"]}')
        exit()
    elif not 'ok' in receivedData:
        print('Server has not responded')
        exit()
    return True

# Getting and processing the command
def commandProcessing(client, key, address):
    while True:
        cmd = input('Pick a command: ')
        try:
            cmd = int(cmd)
            if cmd in range(1, len(COMMANDS)+1):
                break
        except ValueError:
            print('  ==> Invalid command')

    sentFlags = {'SYN': False, 'RES': False, 'CRP': False, 'AUTH': False}
    sequenceNum = getAndIncrementPacet()
    sentData = {'cmd': COMMANDS[cmd-1]}
    payload = json.dumps(sentData).encode()
    packet = buildPacket(sentFlags, sequenceNum, payload, key)

    # Processing  response
    receivedData = json.loads(decryptAES(sendAndReceivePacket(sentFlags, sequenceNum, client, packet, address), key))
    if errorsHandler(receivedData):
        print(f'Server responded with error:\n  ==> {receivedData["err"]}')
    elif not 'ok' in receivedData:
        print(f'Unexpected server response:\n  ==> {receivedData}')
    else:
        print(f'Server responded successfully:\n  ==> {receivedData["ok"]}')
    # Break main function loop if last command was END_CONN
    if COMMANDS[cmd-1] == 'END_CONN': return False
    return True

# Print commands
def printCommands():
    for i in range(len(COMMANDS)):
        print(f'  [{i+1}] {COMMANDS[i]}')
    print('  *SUSPEND, REBOOT and PWROFF are not available for now')

def main():
    config = convertInput()
    # Create UDP socket
    address = (config['server_ip'], config['server_port'])
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind((config["local_addr"], 0))
    print(f'Connecting to {address[0]}:{address[1]}')
    # Calculate AES CBC key as SHA256 hash of the shared secret
    key = hashlib.sha256(diffieHellman(client, address)).digest()
    print('Shared secrets established')

    authenticate(config, client, key)
    print(f'Successfully authenticated as {config["user"]}')
    
    printCommands()
    while commandProcessing(client, key, address):
        pass
    
    client.close()
    print('Closed connection')
    return 0        
 
main()
