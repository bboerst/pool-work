import argparse
import json
import logging
import socket
import sys
import time
import uuid
from datetime import datetime
from urllib.parse import urlparse
import hashlib
import struct
import threading

import pika
from pymongo import MongoClient
from pycoin.symbols.btc import network

LOG = logging.getLogger()

class Watcher:
    def __init__(self, url, userpass, pool_name, rabbitmq_host, rabbitmq_port, rabbitmq_username, rabbitmq_password, rabbitmq_exchange, db_url, db_name, db_username, db_password):
        self.buf = b""
        self.id = 1
        self.userpass = userpass
        self.pool_name = pool_name
        self.rabbitmq_exchange = rabbitmq_exchange
        self.rabbitmq_host = rabbitmq_host
        self.rabbitmq_port = rabbitmq_port
        self.rabbitmq_username = rabbitmq_username
        self.rabbitmq_password = rabbitmq_password
        self.rabbitmq_exchange = rabbitmq_exchange
        self.db_url = db_url
        self.db_name = db_name
        self.db_username = db_username
        self.db_password = db_password
        self.purl = self.parse_url(url)
        self.extranonce1 = None
        self.extranonce2_length = -1
        self.init_socket()
        self.connection = None
        self.channel = None
        self.current_job = None
        self.current_difficulty = None
        self.current_target = None
        self.mining_thread = None
        self.stop_mining = threading.Event()
        self.auth_lock = threading.Lock()
        self.authorized = False

    def parse_url(self, url):
        purl = urlparse(url)
        if purl.scheme != "stratum+tcp":
            raise ValueError(
                f"Unrecognized scheme {purl.scheme}, only 'stratum+tcp' is allowed"
            )
        if purl.hostname is None:
            raise ValueError(f"No hostname provided")
        if purl.port is None:
            raise ValueError(f"No port provided")
        if purl.path != "":
            raise ValueError(f"URL has a path {purl.path}, this is not valid")
        return purl

    def init_socket(self):
        self.sock = socket.socket()
        self.sock.settimeout(600)

    def close(self):
        if self.mining_thread and self.mining_thread.is_alive():
            self.stop_mining.set()
            self.mining_thread.join()
        
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
        LOG.info(f"Disconnected from {self.purl.geturl()}")

    def get_msg(self):
        while True:
            split_buf = self.buf.split(b"\n", maxsplit=1)
            r = split_buf[0]
            if r == b'':
                try:
                    new_buf = self.sock.recv(4096)
                except Exception as e:
                    LOG.debug(f"Error receiving data: {e}")
                    self.close()
                    raise EOFError
                if len(new_buf) == 0:
                    self.close()
                self.buf += new_buf
                continue
            try:
                resp = json.loads(r)
                if len(split_buf) == 2:
                    self.buf = split_buf[1]
                else:
                    self.buf = b""
                return resp
            except (json.decoder.JSONDecodeError, ConnectionResetError) as e:
                LOG.debug(f"Error decoding JSON: {e}")
                new_buf = b""
                try:
                    new_buf = self.sock.recv(4096)
                except Exception as e:
                    LOG.debug(f"Error receiving data: {e}")
                    self.close()
                    raise EOFError
                if len(new_buf) == 0:
                    self.close()
                self.buf += new_buf

    def send_jsonrpc(self, method, params):
        data = {
            "id": self.id,
            "method": method,
            "params": params,
        }
        self.id += 1

        LOG.debug(f"Sending: {data}")
        json_data = json.dumps(data) + "\n"
        self.sock.send(json_data.encode())

        resp = self.get_msg()

        if resp["id"] == 1 and resp["result"] is not None:
            self.extranonce1, self.extranonce2_length = resp["result"][-2:]

        LOG.debug(f"Received: {resp}")
        
    def connect_to_rabbitmq(self):
        credentials = pika.PlainCredentials(self.rabbitmq_username, self.rabbitmq_password)
        self.connection = pika.BlockingConnection(pika.ConnectionParameters(self.rabbitmq_host, self.rabbitmq_port, '/', credentials))
        self.channel = self.connection.channel()
        self.channel.exchange_declare(exchange=self.rabbitmq_exchange, exchange_type='fanout', durable=True)

    def publish_to_rabbitmq(self, message):
        LOG.info(f"Publishing message to RabbitMQ: {json.dumps(message)}")
        self.channel.basic_publish(exchange=self.rabbitmq_exchange, routing_key='', body=json.dumps(message))

    def uint256_from_str(self, s):
        r = 0
        t = struct.unpack("<IIIIIIII", s[:32])
        for i in range(8):
            r += t[i] << (i * 32)
        return r

    def uint256_to_str(self, u):
        rs = []
        for i in range(8):
            rs.append(struct.pack("<I", u & 0xFFFFFFFF))
            u >>= 32
        return b''.join(rs)

    def bits_to_target(self, nbits):
        nbits = int(nbits, 16)
        exp = nbits >> 24
        mant = nbits & 0xffffff
        target = mant * (1 << (8 * (exp - 3)))
        return min(target, 2**256 - 1)  # Ensure the target doesn't exceed the maximum possible value

    def hash_to_int(self, hash_bytes):
        return int.from_bytes(hash_bytes[::-1], byteorder='big')

    def int_to_hash(self, int_value):
        return self.uint256_to_str(int_value)

    def difficulty_to_target(self, difficulty):
        return int((2**256 - 1) // difficulty)

    def mine_block(self):
        if not self.current_job:
            LOG.debug("No current job, exiting mine_block")
            return

        job_id, prevhash, coinb1, coinb2, merkle_branches, version, nbits, ntime, clean_jobs = self.current_job
        
        if self.current_target is None:
            LOG.warning("No target set, using nbits from job")
            self.current_target = self.bits_to_target(nbits)

        LOG.debug(f"Mining with target: {self.current_target}")

        # Construct the block header
        extranonce2 = "00" * self.extranonce2_length
        coinbase = coinb1 + self.extranonce1 + extranonce2 + coinb2
        coinbase_hash = hashlib.sha256(hashlib.sha256(bytes.fromhex(coinbase)).digest()).digest()

        merkle_root = coinbase_hash
        for branch in merkle_branches:
            merkle_root = hashlib.sha256(hashlib.sha256(merkle_root + bytes.fromhex(branch)).digest()).digest()

        block_header = (
            struct.pack("<I", int(version, 16)) +
            bytes.fromhex(prevhash)[::-1] +
            merkle_root +
            bytes.fromhex(ntime) +
            bytes.fromhex(nbits)
        )

        nonce = 0
        start_time = time.time()
        while not self.stop_mining.is_set():
            header_hash = hashlib.sha256(hashlib.sha256(block_header + struct.pack("<I", nonce)).digest()).digest()
            hash_int = self.hash_to_int(header_hash)
            if hash_int < (self.current_target // 100):  # Make the check even more stringent
                LOG.info(f"Found a share after {nonce} attempts")
                LOG.debug(f"Share hash: {hash_int}")
                LOG.debug(f"Current target: {self.current_target}")
                with self.auth_lock:
                    if not self.authorized:
                        LOG.warning("Not authorized, attempting to re-authorize before submitting share")
                        if not self.authorize():
                            LOG.error("Failed to re-authorize, stopping mining")
                            return
                self.submit_share(job_id, extranonce2, ntime, f"{nonce:08x}")
                return
            nonce += 1
            if nonce > 0xffffffff:
                LOG.debug("Nonce overflow, restarting")
                nonce = 0
            if time.time() - start_time > 60:  # Limit mining time to 1 minute
                LOG.debug("Mining time limit reached, restarting")
                return
    
    def start_mining(self):
        with threading.Lock():
            if self.mining_thread and self.mining_thread.is_alive():
                self.stop_mining.set()
                if threading.current_thread() != self.mining_thread:
                    self.mining_thread.join()
                else:
                    LOG.warning("Attempting to stop mining from within the mining thread. Skipping join.")
            
            self.stop_mining.clear()
            self.mining_thread = threading.Thread(target=self.mine_block)
            self.mining_thread.start()
    
    def submit_share(self, job_id, extranonce2, ntime, nonce):
            with self.auth_lock:
                if not self.authorized:
                    LOG.warning("Not authorized, attempting to re-authorize before submitting share")
                    if not self.authorize():
                        LOG.error("Failed to re-authorize, cannot submit share")
                        return

            username = self.userpass.split(":")[0]
            params = [username, job_id, extranonce2, ntime, nonce]
            LOG.info(f"Submitting share: {params}")
            LOG.debug(f"Current target: {self.current_target}")
            LOG.debug(f"Current difficulty: {self.current_difficulty}")
            self.send_jsonrpc("mining.submit", params)

    def handle_mining_submit_response(self, response):
        if response.get("result"):
            LOG.info("Share accepted")
        else:
            error = response.get("error")
            if error:
                LOG.warning(f"Share rejected: {error}")
                if error[1] == "not authorized":
                    LOG.info("Not authorized, attempting to re-authorize...")
                    if self.authorize():
                        LOG.info("Re-authorization successful, resubmitting share")
                        # Extract the parameters from the original submit request
                        original_params = response.get('params', [])
                        if len(original_params) == 5:
                            self.submit_share(original_params[1], original_params[2], original_params[3], original_params[4])
                        else:
                            LOG.error("Invalid parameters for share resubmission")
                    else:
                        LOG.error("Failed to re-authorize after share rejection")
                elif error[1] == "bad_hash":
                    LOG.debug(f"Bad hash. Current target: {self.current_target}")
                    LOG.debug(f"Current difficulty: {self.current_difficulty}")
            else:
                LOG.warning("Share rejected for unknown reason")

    def authorize(self):
        LOG.info("Authorizing with the pool")
        auth_id = self.id
        username, password = self.userpass.split(":")
        self.send_jsonrpc("mining.authorize", [username, password])
        start_time = time.time()
        while time.time() - start_time < 30:  # Wait for up to 30 seconds for auth response
            try:
                auth_response = self.get_msg()
                LOG.debug(f"Received during authorization: {auth_response}")
                if 'id' in auth_response and auth_response['id'] == auth_id:
                    if auth_response.get('result'):
                        LOG.info("Successfully authorized with the pool")
                        self.authorized = True
                        return True
                    else:
                        LOG.error(f"Failed to authorize: {auth_response.get('error', 'Unknown error')}")
                        self.authorized = False
                        return False
                elif 'method' in auth_response:
                    # Handle other messages that might come before the auth response
                    if auth_response['method'] == 'mining.set_difficulty':
                        self.handle_set_difficulty(auth_response)
                    elif auth_response['method'] == 'mining.notify':
                        self.handle_mining_notify(auth_response)
                else:
                    LOG.warning(f"Received unexpected message during authorization: {auth_response}")
            except Exception as e:
                LOG.error(f"Error during authorization: {e}")
        LOG.error("Authorization timed out")
        self.authorized = False
        return False

    def handle_set_difficulty(self, message):
        if 'params' in message and len(message['params']) > 0:
            self.current_difficulty = message['params'][0]
            self.current_target = self.difficulty_to_target(self.current_difficulty)
            LOG.info(f"New difficulty set: {self.current_difficulty}")
            LOG.debug(f"New target: {self.current_target}")
            # Only restart mining if we're not in the authorization process
            if self.authorized:
                self.start_mining()
        else:
            LOG.warning(f"Received invalid set_difficulty message: {message}")
    
    def handle_mining_notify(self, notification):
        self.current_job = notification["params"]
        document = create_notification_document(notification, self.pool_name, self.extranonce1, self.extranonce2_length)
        # insert_notification(document, self.db_url, self.db_name, self.db_username, self.db_password)
        self.publish_to_rabbitmq(document)
        self.start_mining()
    
    def reconnect(self):
        LOG.info(f"Reconnecting to server {self.purl.geturl()}")
        self.close()
        time.sleep(1)
        self.init_socket()
        self.sock.connect((self.purl.hostname, self.purl.port))
        LOG.info(f"Reconnected to server {self.purl.geturl()}")
        self.send_jsonrpc("mining.subscribe", [])
        LOG.info("Resubscribed to pool notifications")
        if not self.authorize():
            LOG.error("Failed to authorize after reconnection")
            raise Exception("Authorization failed after reconnection")

    def get_stratum_work(self, keep_alive=False):
        try:
            self.sock.setblocking(True)
            self.sock.connect((self.purl.hostname, self.purl.port))
            LOG.info(f"Connected to server {self.purl.geturl()}")

            self.send_jsonrpc("mining.subscribe", [])
            LOG.info("Sent subscribe request, waiting for response...")

            while True:
                response = self.get_msg()
                LOG.debug(f"Received message: {response}")

                if 'id' in response and response['id'] == 1:
                    # This is the subscribe response
                    if 'result' in response and response['result'] is not None:
                        LOG.info("Subscribed to pool notifications")
                        if isinstance(response['result'], list) and len(response['result']) >= 2:
                            self.extranonce1 = response['result'][-2]
                            self.extranonce2_length = response['result'][-1]
                            LOG.debug(f"Extranonce1: {self.extranonce1}, Extranonce2 length: {self.extranonce2_length}")
                        break
                    else:
                        LOG.error(f"Failed to subscribe: {response.get('error', 'Unknown error')}")
                        return
                elif 'method' in response:
                    if response['method'] == 'mining.set_difficulty':
                        self.handle_set_difficulty(response)
                    elif response['method'] == 'mining.notify':
                        self.handle_mining_notify(response)
                else:
                    LOG.warning(f"Received unexpected message: {response}")

            if not self.authorize():
                LOG.error("Initial authorization failed, exiting...")
                return

            self.authorized = True
            self.start_mining()  # Start mining after successful authorization
            last_authorize_time = time.time()
            last_subscribe_time = time.time()

            while True:
                try:
                    n = self.get_msg()
                    LOG.debug(f"Received notification: {n}")

                    if "method" in n:
                        if n["method"] == "mining.notify":
                            self.handle_mining_notify(n)
                        elif n["method"] == "mining.set_difficulty":
                            self.handle_set_difficulty(n)
                    elif "error" in n:
                        if n["error"] is not None:
                            LOG.warning(f"Received error from server: {n['error']}")
                            if "not authorized" in str(n["error"]).lower():
                                LOG.info("Not authorized, attempting to re-authorize...")
                                if not self.authorize():
                                    LOG.error("Failed to re-authorize, reconnecting...")
                                    self.reconnect()
                                else:
                                    LOG.info("Re-authorization successful")
                                last_authorize_time = time.time()
                            elif "stale" in str(n["error"]).lower():
                                self.reconnect()
                                last_subscribe_time = time.time()
                                continue
                    elif "result" in n and "id" in n:
                        if n["id"] == self.id - 1:  # This is likely a response to our last mining.submit
                            self.handle_mining_submit_response(n)
                        else:
                            LOG.warning(f"Received unexpected message: {n}")

                    if keep_alive and time.time() - last_subscribe_time > 120:
                        LOG.info("Sending subscribe request to keep connection alive")
                        self.send_jsonrpc("mining.subscribe", [])
                        last_subscribe_time = time.time()

                    if time.time() - last_authorize_time > 300:  # Re-authorize every 5 minutes
                        LOG.info("Periodic re-authorization")
                        if not self.authorize():
                            LOG.error("Failed to re-authorize, reconnecting...")
                            self.reconnect()
                        last_authorize_time = time.time()

                except socket.timeout:
                    LOG.warning("Socket timeout, reconnecting...")
                    self.reconnect()
                    last_subscribe_time = time.time()
                    last_authorize_time = time.time()
                except Exception as e:
                    LOG.error(f"Unexpected error: {e}")
                    self.reconnect()
                    last_subscribe_time = time.time()
                    last_authorize_time = time.time()

        except Exception as e:
            LOG.error(f"Error in get_stratum_work: {e}")
            self.close()
                                        
def create_notification_document(data, pool_name, extranonce1, extranonce2_length):
    notification_id = str(uuid.uuid4())
    now = datetime.utcnow()

    coinbase1 = data["params"][2]
    coinbase2 = data["params"][3]

    coinbase = None
    height = 0
    try:
        coinbase = network.Tx.from_hex(coinbase1 + extranonce1 + "00"*extranonce2_length + coinbase2)
        height = int.from_bytes(coinbase.txs_in[0].script[1:4], byteorder='little')
    except Exception as e:
        print(e)

    document = {
        "_id": notification_id,
        "timestamp": now.isoformat(),  # Convert datetime to ISO 8601 formatted string
        "pool_name": pool_name,
        "height": height,
        "job_id": data["params"][0],
        "prev_hash": data["params"][1],
        "coinbase1": coinbase1,
        "coinbase2": coinbase2,
        "merkle_branches": data["params"][4],
        "version": data["params"][5],
        "nbits": data["params"][6],
        "ntime": data["params"][7],
        "clean_jobs": data["params"][8],
        "extranonce1": extranonce1,
        "extranonce2_length": extranonce2_length
    }

    return document

def insert_notification(document, db_url, db_name, db_username, db_password):
    client = MongoClient(db_url, username=db_username, password=db_password)
    db = client[db_name]
    collection = db.mining_notify

    collection.insert_one(document)
    client.close()
    
def main():
    parser = argparse.ArgumentParser(
        description="Subscribe to a Stratum endpoint and listen for new work"
    )
    parser.add_argument("-u", "--url", required=True, help="The URL of the stratum server, including port. Ex: stratum+tcp://beststratumpool.com:3333")
    parser.add_argument(
        "-up", "--userpass", required=True, help="Username and password combination separated by a colon (:)"
    )
    parser.add_argument(
        "-p", "--pool-name", required=True, help="The name of the pool"
    )
    parser.add_argument(
        "-r", "--rabbitmq-host", default="localhost", help="The hostname or IP address of the RabbitMQ server (default: localhost)"
    )
    parser.add_argument(
        "-rpc", "--rabbitmq-port", default=5672, help="The port of the RabbitMQ server (default: 5672)"
    )
    parser.add_argument(
        "-ru", "--rabbitmq-username", required=True, help="The username for RabbitMQ authentication"
    )
    parser.add_argument(
        "-rp", "--rabbitmq-password", required=True, help="The password for RabbitMQ authentication"
    )
    parser.add_argument(
        "-re", "--rabbitmq-exchange", default="mining_notify_exchange", help="The name of the RabbitMQ exchange (default: mining_notify_exchange)"
    )
    parser.add_argument(
        "-d", "--db-url", default="mongodb://localhost:27017", help="The URL of the MongoDB database (default: mongodb://localhost:27017)"
    )
    parser.add_argument(
        "-dn", "--db-name", required=True, help="The name of the MongoDB database"
    )
    parser.add_argument(
        "-du", "--db-username", required=True, help="The username for MongoDB authentication"
    )
    parser.add_argument(
        "-dp", "--db-password", required=True, help="The password for MongoDB authentication"
    )
    parser.add_argument(
        "-k", "--keep-alive", action="store_true", help="Enable sending periodic subscribe requests to keep the connection alive"
    )
    parser.add_argument(
        "-l", "--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level (default: INFO)"
    )
    
    args = parser.parse_args()

    logging.basicConfig(
        stream=sys.stdout,
        format="%(asctime)s %(levelname)s: %(message)s",
        level=getattr(logging, args.log_level),
    )

    max_retries = 5
    retry_delay = 10  # seconds

    for attempt in range(max_retries):
        try:
            w = Watcher(args.url, args.userpass, args.pool_name, args.rabbitmq_host, args.rabbitmq_port, args.rabbitmq_username, args.rabbitmq_password, args.rabbitmq_exchange, args.db_url, args.db_name, args.db_username, args.db_password)
            w.connect_to_rabbitmq()
            w.get_stratum_work(keep_alive=args.keep_alive)
        except KeyboardInterrupt:
            LOG.info("Keyboard interrupt received, exiting...")
            break
        except Exception as e:
            LOG.error(f"Error occurred: {e}")
            if attempt < max_retries - 1:
                LOG.info(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                LOG.error("Max retries reached, exiting...")
        finally:
            if 'w' in locals():
                w.close()
                if w.connection:
                    w.connection.close()

if __name__ == "__main__":
    main()