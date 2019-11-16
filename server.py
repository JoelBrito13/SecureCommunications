import asyncio
import json
import sys
import base64
import pickle 
import argparse
import coloredlogs, logging
import re
import os
from aio_tcpserver import tcp_server
from symetric_encript import *

logger = logging.getLogger('root')

STATE_CONNECT = 0
STATE_OPEN = 1
STATE_DATA = 2
STATE_CLOSE= 3

#GLOBAL
storage_dir = 'files'

class ClientHandler(asyncio.Protocol):
	def __init__(self, signal):
		"""
		Default constructor
		"""
		self.signal = signal
		self.state = 0
		self.file = None
		self.file_name = None
		self.file_path = None
		self.storage_dir = storage_dir
		self.buffer = 0
		self.peername = ''
		self.aes_key = ''
		self.dh_private = ''
		self.secret = ''

	def connection_made(self, transport) -> None:
		"""
		Called when a client connects
		:param transport: The transport stream to use with this client
		:return:
		"""
		self.peername = transport.get_extra_info('peername')
		logger.info('\n\nConnection from {}'.format(self.peername))
		self.transport = transport
		self.state = STATE_CONNECT


	def data_received(self, data: bytes) -> None:
		"""
        Called when data is received from the client.
        Stores the data in the buffer
        :param data: The data that was received. This may not be a complete JSON message
        :return:
        """
		logger.info('Received: {}'.format(data))
		try:
			message = pickle.loads(data)
			self.buffer += sys.getsizeof(message)
		except:
			logger.exception("Could not decode JSON message: {}".format(message))
			self.transport.close()
			return

		self.on_frame(message)  # Process the frame
		
		if self.buffer > 4096 * 1024 * 1024:  # If buffer is larger than 4M
			logger.warning('Buffer to large')
			self.buffer = 0
			self.transport.close()


	def on_frame(self, message: str) -> None:
		"""
		Called when a frame (JSON Object) is extracted
		:param frame: The JSON object to process
		:return:
		"""

		mtype = message['type'].upper()

		if mtype == 'OPEN':
			ret = self.process_open(message)
		elif mtype == 'KEY':
			ret = self.process_key(message)
		elif mtype == 'DH':
			ret = self.process_dh(message)
		elif mtype == 'DATA':
			ret = self.process_data(message)
		elif mtype == 'CLOSE':
			ret = self.process_close(message)
		else:
			logger.warning("Invalid message type: {}".format(message['type']))
			ret = False
		if not ret:
			try:
				self._send({'type': 'ERROR', 'message': 'See server'})
			except:
				pass # Silently ignore

			logger.info("Closing transport")
			if self.file is not None:
				self.file.close()
				self.file = None

			self.state = STATE_CLOSE
			self.transport.close()


	def process_open(self, message: str) -> bool:
		"""
		Processes an OPEN message from the client
		This message should contain the filename
		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Open: {}".format(message))

		if self.state != STATE_CONNECT:
			logger.warning("Invalid state. Discarding")
			return False

		if not 'file_name' in message:
			logger.warning("No filename in Open")
			return False

		# Only chars and letters in the filename
		file_name = re.sub(r'[^\w\.]', '', message['file_name'])
		file_path = os.path.join(self.storage_dir, file_name)
		if not os.path.exists("files"):
			try:
				os.mkdir("files")
			except:
				logger.exception("Unable to create storage directory")
				return False

		try:
			self.file = open(file_path, "wb")
			logger.info("File open")
		except Exception:
			logger.exception("Unable to open file")
			return False

		self._send({'type': 'OK'})

		self.file_name = file_name
		self.file_path = file_path
		self.state = STATE_OPEN
		return True


	def process_data(self, message: str) -> bool:
		"""
		Processes a DATA message from the client
		This message should contain a chunk of the file
		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Data: {}".format(message))

		if self.state == STATE_OPEN:
			self.state = STATE_DATA
			# First Packet

		elif self.state == STATE_DATA:
			# Next packets
			pass

		else:
			logger.warning("Invalid state. Discarding")
			return False

		try:
			data = message['data']
			if data is None:
				logger.debug("Invalid message. No data found")
				return False

			c_text = message['data']
			bdata = decriptText(key = self.aes_key, cryptogram = c_text)
		except:
			logger.exception("Could not decode base64 content from message.data")
			return False

		try:
			self.file.write(bdata)
			self.file.flush()
		except:
			logger.exception("Could not write to file")
			return False

		return True


	def process_key(self, message: str) -> bool:
		"""
		KEY EXCHANGE
		"""
		logger.info("Process Key: {}".format(message))

		if self.state == STATE_OPEN:
			self.state = STATE_DATA
			# First Packet

		elif self.state == STATE_DATA:
			# Next packets
			pass

		else:
			logger.warning("Invalid state. Discarding")
			return False

		try:
			data = message['key']
			if data is None:
				logger.debug("Invalid message. No data found")
				return False

			self.aes_key = message['key']
			print("New Key: ", self.aes_key)
		except:
			logger.exception("Could not decode base64 content from" + message['key'])
			return False


		self._send({'type': 'OK'})
		return True

	def process_dh(self,message: str) -> bool:
		logger.info("Diffie Hellman Request: {}".format(message))

		if self.state == STATE_OPEN:
			self.state = STATE_DATA
			# First Packet

		elif self.state == STATE_DATA:
			# Next packets
			pass

		else:
			logger.warning("Invalid state. Discarding")
			return False

		try:
			data = load_pem(message['key'])
			params = load_params(message['parameters'])
			if data is None or params is None:
				logger.debug("Invalid message. No data found")
				return False
			# Get clients public
			client_public_p = data
			parameters= params
			# Generate server private
			self.dh_private=dh_private(parameters)
			# Compute secret
			self.secret=self.dh_private.exchange(client_public_p)
			print("Deriving")
			derived_secret=dh_derive(self.secret)
			print(base64.encodebytes(derived_secret))
			
			# Give servers public to client

		except:
			logger.exception("Could not decode base64 content from" + message['key'])
			return False

		self._send({
			'type': 'DH', 'key':self.dh_private.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)
			})
		return True

	def process_close(self, message: str) -> bool:
		"""
		Processes a CLOSE message from the client.
		This message will trigger the termination of this session
		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Close: {}".format(message))

		self.transport.close()
		if self.file is not None:
			self.file.close()
			self.file = None

		self.state = STATE_CLOSE

		return True


	def _send(self, message: str) -> None:
		"""
		Effectively encodes and sends a message
		:param message:
		:return:
		"""
		logger.debug("Send: {}".format(message))

		message_b = pickle.dumps(message)
		self.transport.write(message_b)

def main():
	global storage_dir

	parser = argparse.ArgumentParser(description='Receives files from clients.')
	parser.add_argument('-v', action='count', dest='verbose',
						help='Shows debug messages (default=False)',
						default=0)
	parser.add_argument('-p', type=int, nargs=1,
						dest='port', default=5000,
						help='TCP Port to use (default=5000)')

	parser.add_argument('-d', type=str, required=False, dest='storage_dir',
						default='files',
						help='Where to store files (default=./files)')

	args = parser.parse_args()
	storage_dir = os.path.abspath(args.storage_dir)
	level = logging.DEBUG if args.verbose > 0 else logging.INFO
	port = args.port
	if port <= 0 or port > 65535:
		logger.error("Invalid port")
		return

	if port < 1024 and not os.geteuid() == 0:
		logger.error("Ports below 1024 require eUID=0 (root)")
		return

	coloredlogs.install(level)
	logger.setLevel(level)

	logger.info("Port: {} LogLevel: {} Storage: {}".format(port, level, storage_dir))
	tcp_server(ClientHandler, worker=2, port=port, reuse_port=True)


if __name__ == '__main__':
	main()
