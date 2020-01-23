import sys
import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import os
import time
import uuid
from symetric_encript import *
from certificate import Validator
from cc import SmartCardAuthenticator
from asymetric_encript import rsa_encrypt, rsa_decrypt, rsa_verify_sign

#CriptoAlgorithm, dh_parameters, dh_private, load_pem, load_params, get_mac, dh_derive, ENCODING_PKC3, ENCODING_PUBLIC_KEY


logger = logging.getLogger('root')


STATE_CONNECT   = 0
STATE_LOGIN     = 1
STATE_CHALLENGE = 2
STATE_PRE_KEY   = 3
STATE_OPEN      = 4
STATE_DATA      = 5
STATE_NEW_KEY   = 6
STATE_CLOSE     = 7

class ClientProtocol(asyncio.Protocol):
    """
    Client that handles a single client
    """

    def __init__(self, file_name, loop, algorithm,user,auth_type):
        """
        Default constructor
        :param file_name: Name of the file to send
        :param loop: Asyncio Loop to use
        """
        self.file_name = file_name
        self.loop = loop
        self.user=user
        self.auth_type=auth_type
        self.state = STATE_CONNECT  # Initial State
        self.buffer = ''  # Buffer to receive data chunks
        self.nonce = ''
        self.validator = Validator()
        self.smartcart = SmartCardAuthenticator()
        self.tell = 0     
        self.cripto_algorithm = CriptoAlgorithm(algorithm=algorithm[0])
        self.server_cert = None

    def connection_made(self, transport) -> None:
        """
        Called when the client connects.
        :param transport: The transport stream to use for this client
        :return: No return
        """
        self.state = STATE_CONNECT
        self.transport = transport

        logger.debug('Connected to Server')
        self.state = STATE_CONNECT
        self.server_authentication_start()


    def data_received(self, data: str) -> None:
        """
        Called when data is received from the server.
        Stores the data in the buffer
        :param data: The data that was received. This may not be a complete JSON message
        :return:
        """
        logger.debug('Received: {}'.format(data))
        try:
            self.buffer += data.decode()
        except:
            logger.exception('Could not decode data from client')

        idx = self.buffer.find('\r\n')

        while idx >= 0:  # While there are separators
            frame = self.buffer[:idx + 2].strip()  # Extract the JSON object
            self.buffer = self.buffer[idx + 2:]  # Removes the JSON object from the buffer

            self.on_frame(frame)  # Process the frame
            idx = self.buffer.find('\r\n')

        if len(self.buffer) > 4096 * 1024 * 1024:  # If buffer is larger than 4M
            logger.warning('Buffer to large')
            self.buffer 
            self.state = STATE_CLOSE
            self.buffer= ''
            self.transport.close()

    def on_frame(self, frame: str) -> None:
        """
        Processes a frame (JSON Object)
        :param frame: The JSON Object to process
        :return:
        """

        logger.debug("Frame: {}".format(frame))
        try:
            message = json.loads(frame)
        except:
            logger.exception("Could not decode the JSON message")
            
            self.state = STATE_CLOSE
            self.transport.close()
            return

        mtype = message['type']
        
        if mtype == "SERVER_AUTH_REP":
            logger.info("Requesting Certificate")
            self.server_authentication_verify(message)
        elif mtype == "CHALLENGE":
            logger.info("Signing with key")
            self.proccess_challenge(message)
        
        elif mtype == 'OK':  # Server replied OK. We can advance the state
            if self.state == STATE_CHALLENGE:
                logger.info("Sending Key")
                self.send_key_generate()
            elif self.state == STATE_PRE_KEY:
                logger.info("Channel open")
                self.send_file_name()

            elif self.state in [ STATE_OPEN , STATE_NEW_KEY ] :
                self.send_file(self.file_name)
            else:
                logger.warning("Ignoring message from server")
            return      

        elif mtype == 'ERROR':
            logger.warning("Got error from server: {}".format(message['message']))
        else:
            logger.warning("Invalid message type")

            self.state = STATE_CLOSE
            self.transport.close()
            self.loop.stop()

    def connection_lost(self, exc):
        """
        Connection was lost for some reason.
        :param exc:
        :return:
        """
        logger.info('The server closed the connection')
        self.loop.stop()

    def server_authentication_start(self):
        self.nonce = uuid.uuid4().bytes
        message = {'type': 'SERVER_AUTH_REQ', 'nonce': base64.b64encode(self.nonce).decode()}
        self._send(message)

    def server_authentication_verify(self, message):
        decoded_certificate = base64.b64decode(message['data'])
        signed_nonce = base64.b64decode(message['nonce'])
        self.server_cert = self.validator.load_cert(decoded_certificate)
        # Verify certificate and signed nonce
        if self.validator.build_issuers([],self.server_cert) and rsa_verify_sign(self.server_cert.public_key(),signed_nonce,self.nonce):
            logger.info("Server Authenticated")
            self.login()
        else:
            logger.info("Server Authentication Failed")
            return False

    def login(self):
        if not self.user:
            user = input("Username: ")
            message = {'type': 'LOGIN', 'data': user, 'auth_type': self.auth_type}
        else:
            message = {'type': 'LOGIN', 'data': self.user[0], 'auth_type': self.auth_type}
        
        self.state = STATE_LOGIN
        self._send(message)

    def proccess_challenge(self,message):
        nonce = base64.b64decode(message['nonce'])
        if self.auth_type == 'smartcard':
            signed_nonce=self.smartcart.sign(nonce)
            message = {'type':'CHALLENGE_REP','nonce':base64.b64encode(signed_nonce).decode(), 'auth': 'smartcard'}
            self._send(message)
            self.state =  STATE_CHALLENGE
            return True
        elif self.auth_type == 'password':
            password = input("Password: ")
            salt = os.urandom(16)
            # First password transformation (server also stores hashed password)
                # ...
            # Second password transformation, concatenation (hashed_password + nonce)
            final=self.cripto_algorithm.derive_key(bytes(password,'utf-8')+nonce,salt)
            message = {'type':'CHALLENGE_REP','nonce':base64.b64encode(final).decode(), 'auth': 'password', 'salt': base64.b64encode(salt).decode()}
            self._send(message)
            self.state =  STATE_CHALLENGE
            return True
        else:
            return False

    
    def send_key_generate(self):
        if self.cripto_algorithm.algorithm == "AES":
            self.cripto_algorithm.initial_vector = os.urandom(16)
            iv = base64.b64encode(self.cripto_algorithm.initial_vector).decode()
            message = {'type': 'KEY_SEND', 'key': None, 'initial_vector': iv}
        else:
            message = {'type': 'KEY_SEND', 'key': None}
        key = self.cripto_algorithm.generate_key()

        cripto_key = rsa_encrypt(self.server_cert.public_key(), key)
        if  self.state != STATE_NEW_KEY:
            self.state = STATE_PRE_KEY
        message['key'] = base64.b64encode(cripto_key).decode()
        self._send(message)


    def send_file(self, file_name: str) -> None:
        """
        Sends a file to the server.
        The file is read in chunks, encoded to Base64 and sent as part of a DATA JSON message
        :param file_name: File to send
        :return:  None
        """
        key_buffer = 0 
        self.state = STATE_DATA

        with open(file_name, 'rb') as f:

            f.seek(self.tell)   #go to last read position
            message = {'type': 'DATA', 'data': None,'MAC': None}
            read_size = 16 * 60
            while True:
                data = f.read(16 * 60)              #960 bytes 

                chipher_data = self.cripto_algorithm.EncriptText(text=data)
                mac = self.cripto_algorithm.get_mac(cipher = chipher_data, algorithm = "SHA512")
                
                message['data'] = base64.b64encode(chipher_data).decode()
                message['MAC'] = base64.b64encode(mac).decode()
                
                self._send(message)
                    
                if len(data) != read_size:
                    break
                key_buffer+=1
                
                if key_buffer == 16:                 #each 15.360 bytes, the key will be changed, or 15 kb
                    self.state = STATE_NEW_KEY
                    self.tell = f.tell()
                    self.send_key_generate()
                    break

            if self.state == STATE_DATA:
                self._send({'type': 'CLOSE'})
                logger.info("File transferred. Closing transport")
            
                self.state = STATE_CLOSE
                self.transport.close()

    def send_file_name(self):
        file_name = self.cripto_algorithm.EncriptText(
            text = bytes(self.file_name, 'ascii')
        )
        cipher_name = base64.b64encode(file_name).decode()

        message = {'type': 'OPEN', 'file_name': cipher_name}
        self.state = STATE_OPEN
        self._send(message)

    def _send(self, message: str) -> None:
        """
        Effectively encodes and sends a message
        :param message:
        :return:
        """
        logger.debug("Send: {}".format(message))
        message_b = (json.dumps(message) + '\r\n').encode()
        self.transport.write(message_b)

def main():
    parser = argparse.ArgumentParser(description='Sends files to servers.')
    parser.add_argument('-v', action='count', dest='verbose',
                        help='Shows debug messages',
                        default=0)
    parser.add_argument('-s', type=str, nargs=1, dest='server', default='127.0.0.1',
                        help='Server address (default=127.0.0.1)')
    parser.add_argument('-p', type=int, nargs=1,
                        dest='port', default=5000,
                        help='Server port (default=5000)')
    parser.add_argument('-a', type=str, nargs=1,
                        dest='algorithm', default=['Salsa20'],
                        help='Algorithm options: Salsa20, AES (default=Salsa20)')
    parser.add_argument('-u', type=str, nargs=1,
                        dest='user', default=None,
                        help='Username to use access the server')
    group = parser.add_mutually_exclusive_group(required=True)
    
    group.add_argument('-password',dest='type',action='store_const',const='password')
    group.add_argument('-smartcard',dest='type',action='store_const',const='smartcard')

    parser.add_argument(type=str, dest='file_name', help='File to send')

    args = parser.parse_args()
    file_name = os.path.abspath(args.file_name)
    level = logging.DEBUG if args.verbose > 0 else logging.INFO
    port = args.port
    server = args.server
    algorithm = args.algorithm
    user = args.user
    authtype = args.type
    coloredlogs.install(level)
    logger.setLevel(level)

    logger.info("Sending file: {} to {}:{} Using {}, LogLevel: {}".format(file_name, server, port, algorithm, level))

    loop = asyncio.get_event_loop()
    coro = loop.create_connection(lambda: ClientProtocol(file_name, loop, algorithm,user,authtype),
                                  server, port)
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()

if __name__ == '__main__':
    main()