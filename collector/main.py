import argparse
import json
import logging
import socket
import sys
import time
import uuid
from datetime import datetime
from urllib.parse import urlparse

import pika
from pymongo import MongoClient
from pycoin.symbols.btc import network

LOG = logging.getLogger()

class Watcher:
    def __init__(self, url, userpass, pool_name, rabbitmq_host, rabbitmq_port, rabbitmq_username, rabbitmq_password, rabbitmq_exchange, db_url, db_name, db_username, db_password, reconnect_threshold):
        self.buf = b""
        self.id = 1
        self.last_notify_time = None
        self.reconnect_threshold = reconnect_threshold
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
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
        LOG.info(f"Disconnected from {self.purl.geturl()}")

    def get_msg(self):
        while True:
            try:
                split_buf = self.buf.split(b"\n", maxsplit=1)
                r = split_buf[0]
                if r == b'':
                    new_buf = self.sock.recv(4096)
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
                except json.decoder.JSONDecodeError as e:
                    LOG.debug(f"Error decoding JSON: {e}")
                    new_buf = self.sock.recv(4096)
                    if len(new_buf) == 0:
                        self.close()
                    self.buf += new_buf
            except TimeoutError as e:
                LOG.warning(f"Timeout occurred: {e}")
                continue
            except ConnectionResetError as e:
                LOG.warning(f"Connection reset by peer: {e}")
                self.close()
                raise EOFError

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

    def get_stratum_work(self):
        self.sock.setblocking(True)
        self.sock.connect((self.purl.hostname, self.purl.port))
        LOG.info(f"Connected to server {self.purl.geturl()}")

        self.send_jsonrpc("mining.subscribe", [])
        LOG.info("Subscribed to pool notifications")

        self.send_jsonrpc("mining.authorize", self.userpass.split(":"))
        LOG.info("Authed with the pool")

        self.last_notify_time = time.time()

        while True:
            try:
                n = self.get_msg()
                LOG.debug(f"Received notification: {n}")

                if "method" in n and n["method"] == "mining.notify":
                    self.last_notify_time = time.time()
                    document = create_notification_document(n, self.pool_name, self.extranonce1, self.extranonce2_length)
                    insert_notification(document, self.db_url, self.db_name, self.db_username, self.db_password)
                    self.publish_to_rabbitmq(document)
            except Exception as e:
                LOG.info(f"Received exception: {e}")
                self.close()
                return

            if time.time() - self.last_notify_time > self.reconnect_threshold:
                LOG.info(f"No mining.notify message received for {self.reconnect_threshold} seconds. Reconnecting...")
                self.close()
                return

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
        "-rt", "--reconnect-threshold", type=int, default=180,
        help="The maximum duration (in seconds) allowed without receiving a 'mining.notify' message before initiating a reconnect (default: 300)"
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
    retry_delay = 1
    retry_count = 0

    while True:
        w = Watcher(args.url, args.userpass, args.pool_name, args.rabbitmq_host, args.rabbitmq_port, args.rabbitmq_username, args.rabbitmq_password, args.rabbitmq_exchange, args.db_url, args.db_name, args.db_username, args.db_password, args.reconnect_threshold)
        try:
            w.connect_to_rabbitmq()
            while True:
                w.get_stratum_work()
        except KeyboardInterrupt:
            break
        except Exception as e:
            LOG.error(f"Unexpected error occurred: {e}")
            retry_count += 1
            if retry_count <= max_retries:
                LOG.info(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff
            else:
                LOG.error("Max retries exceeded. Exiting...")
                break
        finally:
            w.close()
            if w.connection:
                w.connection.close()

if __name__ == "__main__":
    main()