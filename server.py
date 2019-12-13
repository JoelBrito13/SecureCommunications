import asyncio
import json
import sys
import base64
import argparse
import coloredlogs, logging
import re
import os
import uuid
from aio_tcpserver import tcp_server
from symetric_encript import *
from asymetric_encript import *
from certificate import Validator
from asymetric_encript import rsa_encrypt, rsa_decrypt
from cc import SmartCardAuthenticator
#CriptoAlgorithm, dh_parameters, dh_private, load_pem, load_params, dh_derive, ENCODING_PUBLIC_KEY


logger = logging.getLogger('root')

STATE_CONNECT = 0
STATE_READY = 1
STATE_OPEN = 2
STATE_DATA = 3
STATE_CLOSE= 4

#GLOBAL
storage_dir = 'files'

class ClientHandler(asyncio.Protocol):
	def __init__(self, signal):
		"""
		Default constructor
		"""
		self.signal = signal
		self.state = STATE_CONNECT
		self.file = None
		self.file_name = None
		self.file_path = None
		self.validator = Validator()
		self.storage_dir = storage_dir
		self.resources_dir = os.path.join(os.getcwd(),"resources")
		self.certificate_file = "SIO_Server.crt"
		self.key_file = "SIO_Server_Key.pem"
		# Temporary
		self.nonce=''
		self.user_cert_file=''
		###########
		self.buffer = ''
		self.peername = ''
		self.cert = None


	def connection_made(self, transport) -> None:
		"""
		Called when a client connects
		:param transport: The transport stream to use with this client
		:return:
		"""
		self.peername = transport.get_extra_info('peername')
		logger.info('\n\nConnection from {}'.format(self.peername))
		self.transport = transport
		#self.state = STATE_DH


	def data_received(self, data: bytes) -> None:
		"""
		Called when data is received from the client.
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


	def on_frame(self, frame: str) -> None:
		"""
		Called when a frame (JSON Object) is extracted
		:param frame: The JSON object to process
		:return:
		"""
		try:
			message = json.loads(frame)
		except:
			logger.exception("Could not decode JSON message: {}".format(frame))
			self.transport.close()
			return

		mtype = message['type'].upper()

		if mtype == 'KEY_SEND':
			ret = self.process_key(message)
		elif mtype == 'SERVER_AUTH_REQ':
			ret = self.send_certificate()
		elif mtype == 'LOGIN':
			ret = self.process_login(message)
		elif mtype == 'CHALLENGE_REP':
			ret = self.process_challenge(message)
		elif mtype == 'OPEN':
			ret = self.process_open(message)
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


	def process_key(self,message: str) -> bool:
		try:
			if 'initial_vector' in message: 
				iv = base64.b64decode(message['initial_vector'])
				algorithm = "AES"
			else:
				iv = None
				algorithm ="Salsa20"

			client_key = base64.b64decode(message['key'])

			# Access servers private key and decrypt secret
			fname = os.path.join(self.resources_dir,"keys",self.key_file)
			symetric_key = rsa_decrypt(rsa_private_file(fname,None), client_key)
			

			self.cripto_algorithm = CriptoAlgorithm(key = symetric_key, algorithm=algorithm, initial_vector=iv)
			self.state = STATE_READY

		except:
			logger.exception("Could not decode base64 content from" + message['key'])
			self._send({'type':'ERROR', 'message': 'Could not decode base64 content from key'})
			return False

		self._send({'type': 'OK'})
		return True


	def send_certificate(self):
		try:
			fi = os.path.join(self.resources_dir,self.certificate_file)
			self.cert = self.validator.load_cert_file(fi)
		except:
			print("Server certificate not found")
			return False
		message = {'type': 'SERVER_AUTH_REP', 'data': base64.b64encode(self.cert.public_bytes(Encoding.PEM)).decode()}
		self._send(message)
		return True
		

	def process_login(self,message):
		user = message['data']
		with open(os.path.join(self.resources_dir,"users.csv"),"r") as users_file:
			user_info=[l.split(",") for l in users_file if l.split(",")[0]==user][0]
			# If user exists
			if user_info:
				self.nonce = uuid.uuid4().bytes
				self.user_cert_file=user_info[3]
				message = {'type': 'CHALLENGE', 'nonce': base64.b64encode(self.nonce).decode()}
				self._send(message)
				return True
		return False


	def process_challenge(self,message):
		signed_nonce = base64.b64decode(message['nonce'])
		fname = os.path.join(self.resources_dir,self.user_cert_file)
		user_cert=self.validator.load_cert_file(fname)
		user_pk=user_cert.public_key()
		try:
			user_pk.verify(
				signed_nonce,
				self.nonce,
				padding.PKCS1v15(),
				hashes.SHA1()
			)
			logger.info("User signature verified")
			if self.validator.build_issuers([],user_cert):
				logger.info(f"User certificate verified ({fname})")
				logger.info("User Authenticated")
				self._send({'type': 'OK'})
				return True
			else:
				logger.info("Invalid user certificate")
		except:
			logger.info("Bad user signature")
			return False
		return False


	def process_open(self, message: str) -> bool:
		"""
		Processes an OPEN message from the client
		This message should contain the filename
		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.info("Process Open: {}".format(message))

		if self.state != STATE_READY:
			logger.warning("Invalid state. Discarding")
			return False

		if not 'file_name' in message:
			logger.warning("No filename in Open")
			return False
		cipher_name = base64.b64decode(message['file_name'])
		b_name = self.cripto_algorithm.DecriptText(cipher_name)
		
		# Only chars and letters in the filename
		file_name = re.sub(r'[^\w\.]', '', b_name.decode('ascii'))
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
		logger.info("Process Data: {}".format(message))

		if self.state == STATE_OPEN  or self.state == STATE_DATA or self.state == STATE_READY:
			# Next packets
			pass

		else:
			logger.warning("Invalid state. Discarding")
			return False

		self.state = STATE_DATA

		try:
			data = message['data']
			if data is None:
				logger.debug("Invalid message. No data found")
				return False
	  
			c_text = base64.b64decode(message['data'])
			client_mac = base64.b64decode(message['MAC'])

			verification_mac = self.cripto_algorithm.get_mac(cipher = c_text, algorithm = "SHA512")
			
			if verification_mac == client_mac:
				logger.debug("Valid MAC")         
				bdata = self.cripto_algorithm.DecriptText(ciphertext = c_text)
			else:
				logger.exception("Invalid MAC")
				return False
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

		message_b = (json.dumps(message) + '\r\n').encode()
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
