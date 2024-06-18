import eventlet
eventlet.monkey_patch()

from flask import Flask, render_template, send_file, request, jsonify, after_this_request, g
import gzip
import io
from datetime import datetime
from flask_socketio import SocketIO
from flask_cors import CORS
from pycoin.symbols.btc import network
from bson import json_util
import json
import logging
import requests
import time
import signal
import string
import sys
import os
import pika

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": ["http://127.0.0.1:8000", "http://localhost:8000", "https://poolwork.live", "https://stratum.work"]}})
socketio = SocketIO(app, cors_allowed_origins=["http://127.0.0.1:8000", "http://localhost:8000", "https://poolwork.live", "https://stratum.work"])

@app.after_request
def add_headers(response):
    response.headers['Access-Control-Allow-Origin'] = 'https://stratum.work'
    return response

connection = None
channel = None
connected_clients = set()

# Dictionary to store cached pool hashrate and transaction results
transaction_cache = {}
hashrate_cache = {}

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

pool_name_mapping = {
    "Foundry USA": "foundryusa",
    # Add more mappings for other pool names
}

# RabbitMQ connection details
rabbitmq_host = os.environ.get('RABBITMQ_HOST')
rabbitmq_port = os.environ.get('RABBITMQ_PORT')
rabbitmq_username = os.environ.get('RABBITMQ_USERNAME')
rabbitmq_password = os.environ.get('RABBITMQ_PASSWORD')
rabbitmq_exchange = os.environ.get('RABBITMQ_EXCHANGE')

def process_row_data(row):
    coinbase1 = row['coinbase1']
    coinbase2 = row['coinbase2']
    extranonce1 = row['extranonce1']
    extranonce2_length = row['extranonce2_length']
    prev_hash = row['prev_hash']
    version = row['version']
    merkle_branches = row['merkle_branches']

    coinbase_hex = coinbase1 + extranonce1 + '00' * extranonce2_length + coinbase2
    coinbase_tx = network.Tx.from_hex(coinbase_hex)
    output_value = sum(tx_out.coin_value for tx_out in coinbase_tx.txs_out) / 1e8
    height = int.from_bytes(coinbase_tx.txs_in[0].script[1:4], byteorder='little')
    prev_block_hash = get_prev_block_hash(prev_hash)
    block_version = int(version, 16)
    first_transaction = bytes(reversed(bytes.fromhex(merkle_branches[0]))).hex() if merkle_branches else 'empty block'
    fee_rate = get_transaction_fee_rate(first_transaction)
    merkle_branch_colors = precompute_merkle_branch_colors(merkle_branches)
    script_sig_ascii = extract_coinbase_script_ascii(coinbase_tx)
    
    pool_name = row['pool_name']
    hashrate = get_pool_hashrate(pool_name)

    processed_row = {
        'pool_name': row['pool_name'],
        'timestamp': row['timestamp'],
        'hashrate': hashrate,
        'height': height,
        'prev_block_hash': prev_block_hash,
        'block_version': block_version,
        'coinbase_raw': coinbase_hex,
        'version': version,
        'nbits': row['nbits'],
        'ntime': row['ntime'],
        'coinbase_script_ascii': script_sig_ascii,
        'clean_jobs': row['clean_jobs'],
        'first_transaction': first_transaction,
        'fee_rate': fee_rate,
        'merkle_branches': merkle_branches,
        'merkle_branch_colors': merkle_branch_colors,
        'coinbase_output_value': output_value
    }

    return processed_row

def get_prev_block_hash(prev_hash):
    prev_block_hash = bytes.fromhex(prev_hash)[::-1].hex()
    return prev_block_hash

def get_transaction_fee_rate(first_transaction):
    if first_transaction == 'empty block':
        return ''

    # Check if the transaction result is already cached
    if first_transaction in transaction_cache:
        cached_result, cpfp_result, expiration_time = transaction_cache[first_transaction]
        if time.time() < expiration_time:
            return cpfp_result if cpfp_result is not None else cached_result

    fee_rate = None
    cpfp_fee_rate = None

    try:
        # Check if the transaction is a CPFP transaction
        cpfp_response = requests.get(f'https://mempool.space/api/v1/cpfp/{first_transaction}')
        logger.info(f"mempool.space API - CPFP tx response: {cpfp_response.status_code} - {first_transaction}")
        if cpfp_response.status_code == 200:
            cpfp_data = cpfp_response.json()
            if 'effectiveFeePerVsize' in cpfp_data:
                cpfp_fee_rate = round(cpfp_data['effectiveFeePerVsize'])
                # Cache the CPFP result for 5 minutes
                expiration_time = time.time() + 300  # 5 minutes in seconds
                transaction_cache[first_transaction] = (None, cpfp_fee_rate, expiration_time)
                return cpfp_fee_rate

        # If not a CPFP transaction, calculate normal fee rate
        response = requests.get(f'https://mempool.space/api/tx/{first_transaction}')
        logger.info(f"mempool.space API - Reg tx response: {response.status_code} - {first_transaction}")
        if response.status_code == 200:
            data = response.json()
            fee = data.get('fee')
            weight = data.get('weight')
            if fee is not None and weight is not None:
                fee_rate = round(fee / (weight / 4))
                # Cache the normal result for 5 minutes
                expiration_time = time.time() + 300  # 5 minutes in seconds
                transaction_cache[first_transaction] = (fee_rate, None, expiration_time)
                return fee_rate

        return 'not found'
    except requests.exceptions.RequestException as e:
        logger.exception(f"Error fetching transaction fee rate for {first_transaction}")
        return 'Error'

def extract_coinbase_script_ascii(coinbase_tx):
    # Get the script_sig in hex from the input of the coinbase transaction
    script_sig_hex = coinbase_tx.txs_in[0].script.hex()
    
    # Convert the script_sig hex to ASCII and filter out non-printable characters
    return ''.join(filter(lambda x: x in string.printable, bytes.fromhex(script_sig_hex).decode('ascii', 'replace')))

def precompute_merkle_branch_colors(merkle_branches):
    colors = []
    for branch in merkle_branches:
        hash_value = branch
        hue = abs(hash_code(hash_value) % 360)
        lightness = 60 + (hash_code(hash_value) % 25)
        color = f'hsl({hue}, 100%, {lightness}%)'
        colors.append(color)
    return colors

def hash_code(text):
    return sum(ord(char) for char in text)

def get_pool_hashrate(pool_name):
    api_pool_name = pool_name_mapping.get(pool_name)
    if not api_pool_name:
        return None

    current_time = time.time()
    if pool_name in hashrate_cache and current_time < hashrate_cache[pool_name]["expiry"]:
        return hashrate_cache[pool_name]["value"]

    url = f"https://mempool.space/api/v1/mining/pool/{api_pool_name}/hashrate"
    response = requests.get(url)
    data = response.json()

    if not data:
        return None

    latest_entry = data[0]
    timestamp = latest_entry["timestamp"]
    avg_hashrate = latest_entry["avgHashrate"]

    if avg_hashrate >= 10**18:
        hashrate = f"{avg_hashrate / 10**18:.2f} EH/s"
    else:
        hashrate = f"{avg_hashrate / 10**15:.2f} PH/s"

    cache_expiry = timestamp + (7 * 24 * 60 * 60) + (3 * 60 * 60)  # 1 week and 3 hours in seconds
    hashrate_cache[pool_name] = {"value": hashrate, "expiry": cache_expiry}

    return hashrate

def consume_messages():
    global connection, channel

    credentials = pika.PlainCredentials(rabbitmq_username, rabbitmq_password)
    connection = pika.BlockingConnection(pika.ConnectionParameters(rabbitmq_host, rabbitmq_port, '/', credentials))
    channel = connection.channel()

    # Declare the exchange as a fanout exchange
    channel.exchange_declare(exchange=rabbitmq_exchange, exchange_type='fanout', durable=True)

    # Let RabbitMQ generate a unique queue name for each consumer
    result = channel.queue_declare(queue='', exclusive=True)
    queue_name = result.method.queue

    # Bind the generated queue to the fanout exchange
    channel.queue_bind(exchange=rabbitmq_exchange, queue=queue_name)

    def callback(ch, method, properties, body):
        try:
            message = json.loads(body)
            processed_message = process_row_data(message)
            for client_id in connected_clients:
                socketio.emit('mining_data', processed_message, room=client_id)
        except Exception as e:
            logger.exception(f"Error processing message: {e}")

    channel.basic_consume(queue=queue_name, on_message_callback=callback, auto_ack=True)

    logger.info('Started consuming messages from the exchange')
    channel.start_consuming()
    
@socketio.on('connect')
def handle_connect():
    logger.info('Client connected')
    if len(connected_clients) == 0:
        socketio.start_background_task(target=consume_messages)
    connected_clients.add(request.sid)

@socketio.on('disconnect')
def handle_disconnect():
    logger.info('Client disconnected')
    connected_clients.remove(request.sid)
    if len(connected_clients) == 0:
        if channel and connection:
            channel.stop_consuming()
            connection.close()

def gzip_response(response):
    accept_encoding = request.headers.get('Accept-Encoding', '')

    if 'gzip' not in accept_encoding.lower():
        return response

    response.direct_passthrough = False

    if (response.status_code < 200 or
        response.status_code >= 300 or
        'Content-Encoding' in response.headers):
        return response

    gzip_buffer = io.BytesIO()
    gzip_file = gzip.GzipFile(mode='wb', compresslevel=5, fileobj=gzip_buffer)
    gzip_file.write(response.data)
    gzip_file.close()

    response.data = gzip_buffer.getvalue()
    response.headers['Content-Encoding'] = 'gzip'
    response.headers['Content-Length'] = len(response.data)

    return response

@app.route('/')
def index():
    socket_url = os.environ.get('SOCKET_URL', 'https://stratum.work')
    return render_template('index.html', SOCKET_URL=socket_url)

@app.route('/static/bitcoinjs-lib.js')
def serve_js():
    return send_file('static/bitcoinjs-lib.js', mimetype='application/javascript')

def handle_sigterm(*args):
    logger.info("Received SIGTERM signal. Shutting down gracefully.")
    socketio.stop()
    sys.exit(0)
    
if __name__ == "__main__":
    socketio.run(app)
