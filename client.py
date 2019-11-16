import sys
import asyncio
import json
import pickle 
import base64
import argparse
import coloredlogs, logging
import os
from symetric_encript import generateKey, encryptAesSalsa20, decryptAesSalsa20

logger = logging.getLogger('root')

STATE_CONNECT = 0
STATE_OPEN = 1
STATE_DATA = 2
STATE_CLOSE = 3


class ClientProtocol(asyncio.Protocol):
    """
    Client that handles a single client
    """

    def __init__(self, file_name, loop):
        """
        Default constructor
        :param file_name: Name of the file to send
        :param loop: Asyncio Loop to use
        """

        self.file_name = file_name
        self.loop = loop
        self.state = STATE_CONNECT  # Initial State
        self.buffer = ''  # Buffer to receive data chunks
        self.secret= ''
        self.dh_private = ''
        self.aes_key = generateKey(32)
		self.salsa_key = generateKey(32)
		self.initial_vector = os.urandom(16)

    def connection_made(self, transport) -> None:
        """
        Called when the client connects.
        :param transport: The transport stream to use for this client
        :return: No return
        """
        self.transport = transport

        logger.debug('Connected to Server')
        
        message = {'type': 'OPEN', 'file_name': self.file_name}
        self._send(message)

        self.state = STATE_OPEN


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
            self.buffer = ''
            self.transport.close()

    def on_frame(self, message: str) -> None:
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
            self.transport.close()
            return

        mtype = message.get('type', None)


        mtype = message['type']

        if mtype == 'OK':  # Server replied OK. We can advance the state
            if self.state == STATE_OPEN:
                logger.info("Channel open")
                self.dh_start()
                #self.send_file(self.file_name)
            elif self.state == STATE_DATA:  # Got an OK during a message transfer.
                # Reserved for future use
                pass
            else:
                logger.warning("Ignoring message from server")
            return
        elif mtype == 'ERROR':
            logger.warning("Got error from server: {}".format(message['data']))
        elif mtype == 'DH':
            self.dh_finalize(message['key'])
        else:
            logger.warning("Invalid message type")


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

    def send_file(self, file_name: str) -> None:
        """
        Sends a file to the server.
        The file is read in chunks, encoded to Base64 and sent as part of a DATA JSON message
        :param file_name: File to send
        :return:  None
        """

        with open(file_name, 'rb') as f:
            message = {'type': 'DATA', 'data': None}
            read_size = 16 * 60
            while True:
                p_text = f.read(16 * 60)
                print("SelfKey", self.key, " text", p_text)
                data = encryptAesSalsa20(key_aes=self.aes_key, keysalsa=self.salsa_key, text=self.p_text, iv=self.initial_vector)
     
                message['data'] = base64.b64encode(data).decode()
                self._send(message)
                    
                if len(p_text) != read_size:
                    print(len(p_text))
                    break

            self._send({'type': 'CLOSE'})
            logger.info("File transferred. Closing transport")
            self.transport.close()
    
    def dh_start(self):
        parameters=dh_parameters()
        self.dh_private=dh_private(parameters)
        # TODO - change "key" naming
        message = {
            'type': 'DH',
            'parameters': parameters.parameter_bytes(Encoding.PEM,ParameterFormat.PKCS3),
            'key': self.dh_private.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)
            }
        self._send(message)

    def dh_finalize(self,server_key):

        #print(f"Client Private: {base64.encodebytes(self.dh_private.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption))}")
        self.secret=self.dh_private.exchange(load_pem(server_key))
        derived_secret=dh_derive(self.secret)
        print(base64.encodebytes(derived_secret))


    def _send(self, message: str) -> None:
        """
        Effectively encodes and sends a message
        :param message:
        :return:
        """
        logger.debug("Send: {}".format(message))
        print(message)
        message_b = json.dumps(message)
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

    parser.add_argument(type=str, dest='file_name', help='File to send')

    args = parser.parse_args()
    file_name = os.path.abspath(args.file_name)
    level = logging.DEBUG if args.verbose > 0 else logging.INFO
    port = args.port
    server = args.server

    coloredlogs.install(level)
    logger.setLevel(level)

    logger.info("Sending file: {} to {}:{} LogLevel: {}".format(file_name, server, port, level))

    loop = asyncio.get_event_loop()
    coro = loop.create_connection(lambda: ClientProtocol(file_name, loop),
                                  server, port)
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()

if __name__ == '__main__':
    main()