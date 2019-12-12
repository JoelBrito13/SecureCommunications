import sys
import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import os
import time
from symetric_encript import *
from certificate import Validator
from cc import SmartCardAuthenticator
#CriptoAlgorithm, dh_parameters, dh_private, load_pem, load_params, get_mac, dh_derive, ENCODING_PKC3, ENCODING_PUBLIC_KEY


logger = logging.getLogger('root')

STATE_CONNECT = 0
STATE_DH = 1
STATE_OPEN = 2
STATE_DATA = 3
STATE_CLOSE = 4


class ClientProtocol(asyncio.Protocol):
    """
    Client that handles a single client
    """

    def __init__(self, file_name, loop, algorithm,user):
        """
        Default constructor
        :param file_name: Name of the file to send
        :param loop: Asyncio Loop to use
        """
        self.file_name = file_name
        self.loop = loop
        self.user=user
        self.state = STATE_CONNECT  # Initial State
        self.buffer = ''  # Buffer to receive data chunks
        self.dh_private = ''
        self.validator = Validator()
        self.smartcart = SmartCardAuthenticator()
        self.tell = 0     
        self.cripto_algorithm = CriptoAlgorithm(algorithm=algorithm[0])

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

        mtype = message.get('type', None)

        mtype = message['type']
        if mtype == 'DH_REP':
            self.dh_finalize(message)
            if self.state == STATE_CONNECT:
                self.send_file_name()
            elif self.state == STATE_DH:
                logger.info("Channel reopen")
                self.send_file(self.file_name)
        elif mtype == "SERVER_AUTHEN_REP":
            self.server_authentication_verify(message)
        elif mtype == "CHALLENGE":
            self.sign(message)
        elif mtype == 'OK':  # Server replied OK. We can advance the state
            if self.state == STATE_OPEN:
                logger.info("Channel open")
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
        message = {'type': 'SERVER_AUTHEN_REQ', 'parameters': None}
        self._send(message)

    def server_authentication_verify(self,message):
        decoded = base64.b64decode(message['cert'])
        cert = self.validator.load_cert(decoded)
        if self.validator.build_issuers([],cert):
            logger.info("Server Authenticated")
            self.login()
        else:
            logger.info("Server Authentication Failed")
            return False

    def login(self):
        if not self.user:
            user = input("Username: ")
            message = {'type': 'LOGIN', 'id': user}
        else:
            message = {'type': 'LOGIN', 'id': self.user[0]}
        self._send(message)

    def sign(self,message):
        nonce = message['nonce']
        signed_nonce=self.smartcart.sign(nonce)
        message = {'type':'CHALLENGE_REP','nonce':base64.b64encode(signed_nonce).decode()}
        self._send(message)
        return True

    #def smartcard_authentication(self):
        #cert = self.smartcart.get_user_certificate()
        #message = {'type': 'CLIENT_AUTHEN_REQ', 'cert': base64.b64encode(cert.public_bytes(Encoding.PEM)).decode()}
        #self._send(message)

    def dh_start(self):
        if self.cripto_algorithm.algorithm == "AES":
            self.cripto_algorithm.initial_vector = os.urandom(16)
            iv = base64.b64encode(self.cripto_algorithm.initial_vector).decode()
            message = {'type': 'DH_REQ', 'parameters': None,'key': None, 'initial_vector': iv }
        else:
            message = {'type': 'DH_REQ', 'parameters': None,'key': None}
    

        parameters=dh_parameters()
        self.dh_private=dh_private(parameters)
        # TODO - change "key" naming
        
        message['parameters'] =  base64.b64encode(
            parameters.parameter_bytes(
                Encoding.PEM,ParameterFormat.PKCS3)
        ).decode()

        message['key'] = base64.b64encode(
            self.dh_private
            .public_key()
            .public_bytes(
                Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)
        ).decode()
        self._send(message)

    def dh_finalize(self, message):
        server_key = base64.b64decode(message['key'])
        secret=self.dh_private.exchange(load_pem(server_key))
        symetric_key=dh_derive(secret)
        self.cripto_algorithm.key = symetric_key

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
                    self.state = STATE_DH
                    self.tell = f.tell()
                    self.dh_start()
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

    parser.add_argument(type=str, dest='file_name', help='File to send')

    args = parser.parse_args()
    file_name = os.path.abspath(args.file_name)
    level = logging.DEBUG if args.verbose > 0 else logging.INFO
    port = args.port
    server = args.server
    algorithm = args.algorithm
    user = args.user

    coloredlogs.install(level)
    logger.setLevel(level)

    logger.info("Sending file: {} to {}:{} Using {}, LogLevel: {}".format(file_name, server, port, algorithm, level))

    loop = asyncio.get_event_loop()
    coro = loop.create_connection(lambda: ClientProtocol(file_name, loop, algorithm,user),
                                  server, port)
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()

if __name__ == '__main__':
    main()