import hashlib
import json
from datetime import datetime
import pymysql
from time import time
from uuid import uuid4
from flask import Flask, jsonify, request
from urllib.parse import urlparse
from werkzeug.middleware.proxy_fix import ProxyFix
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import requests
import re
import redis
import sys


DIFFICULTY_COUNT = 3

class Blockchain(object):

    def __init__(self):
        self.chain = []
        self.currentTransaction = []
        self.nodes = set()  # 存储区块链网络中所有节点信息
        # Create the genesis block
        self.new_block(proof=100, previous_hash=1)
        self.neighbor = []
        try:
            self.conn = pymysql.connect(host='localhost', port=3306,
                                        user='root', password='123456',
                                        database='mysql', charset='utf8')
        except Exception as error:
            print('There is a problem connecting to MySQL！')
            print('Reason for failure：', error)
            exit()
        self.hostname = 'localhost'
        self.portnumber = 6379
        self.password = '654321'
        self.last_index = 0
        self.r = None

    def addNeighbor(self, neighbor):
        self.neighbor.append(neighbor)

    def broadcastBC(self):
        myChain = []
        for block in self.blockchain:
            myChain.append(self.blocktoJson(block))
        data = {
            'blocks': str(myChain),
            'length': len(myChain)
        }
        for neighbor in self.neighbor:
            response = requests.post(f'http://localhost:{neighbor}/broadcast', data=data)
            if response.status_code == 200:
                print('广播成功')
            else:
                print('广播失败')

    def blocktoJson(block):
        dir = {}
        dir["index"] = block['index']
        dir["transactions"] = block['transactions']
        dir["timestamp"] = block['timestamp']
        dir["previous_hash"] = block['previous_hash']
        dir["current_hash"] = block['current_hash']
        dir["difficulty"] = block['difficulty']
        dir["proof"] = block['proof']
        dir['transactions'] = "".join('%s' % a for a in block['transactions'])
        return dir

    def register_node(self, address):
        """
            address: Address of node. 'http://127.0.0.1:5000'
        """
        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    def valid_chain(self, chain):

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            # Check that the hash of the block is correct
            last_block_hash = self.hash(last_block)
            if block['previous_hash'] != last_block_hash:
                return False

            if not self.valid_proof(last_block['proof'], block['proof'], block['difficulty']):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
            replacing our chain with the longest one in the network.
        """

        neighbours = self.nodes
        new_chain = None

        max_length = len(self.chain)

        for node in neighbours:
            response = requests.get(f'http://{node}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        if new_chain:
            self.chain = new_chain
            return True

        return False


    def new_block(self, proof, previous_hash=None):

        idx = len(self.chain) + 1
        t = hashlib.sha256(" ".join('%s' %a for a in self.currentTransaction).encode('utf-8')).hexdigest()
        i = hashlib.sha256(str(idx).encode('utf-8')).hexdigest()
        ts = hashlib.sha256(datetime.now().strftime("%m%d%Y%H%M%S").encode('utf-8')).hexdigest()
        ph = hashlib.sha256(str(previous_hash).encode('utf-8')).hexdigest()
        p = hashlib.sha256(str(proof).encode('utf-8')).hexdigest()
        crt_hash = hashlib.sha256(str(t + i + ts + ph + p).encode('utf-8')).hexdigest()

        block = {
            'index': len(self.chain) + 1,
            'transactions': self.currentTransaction,
            'timestamp': time(),
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
             'current_hash': crt_hash,
            'difficulty': 5,
            'proof': proof,
        }
        if block['index'] == 1:
            block['current_hash'] = '0' * block['difficulty'] + block['current_hash']

        self.currentTransaction = []
        self.chain.append(block)
        return block


    def new_transaction(self, sender, recipient, amount):

        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()
        message = sender.encode('utf-8')
        signature = sign(private_key, message)

        ver_res = verify(public_key, signature, message)
        if(ver_res == False):
            return Exception("Failed to add transaction.")

        self.currentTransaction.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        })

        return self.last_block['index'] + 1


    @staticmethod
    def hash(block):
        return block['current_hash'];

    @property
    def last_block(self):
        return self.chain[-1]

    def proof_of_work(self, lastProof,difficulty):
        proof = 0
        while self.valid_proof(lastProof, proof, difficulty) is False:
            proof += 1
        return proof

    @staticmethod
    def valid_proof(lastProof, proof, difficulty):
        guess = f'{lastProof}{proof}{difficulty}'.encode()
        guessHash = hashlib.sha256(guess).hexdigest()
        zerobits = ['0'] * difficulty
        return guessHash[:difficulty] == ''.join(zerobits)

    def change_difficulty(self, block):
        # only change if more than 2*count is no the chain
        if (len(self.chain) <= DIFFICULTY_COUNT * 2):
            return block['difficulty']
        # calculate average of last three by curr block's timestamp - prev timestamp
        this_round_time = (block['timestamp'] - self.chain[-DIFFICULTY_COUNT]['timestamp'])
        last_round_time = (self.chain[-DIFFICULTY_COUNT]['timestamp'] -
                           self.chain[-(DIFFICULTY_COUNT * 2)]['timestamp'])
        # if this round time > twice last round time, reduce difficulty
        if (this_round_time > last_round_time*2):
            return block['difficulty'] - 1
        # if this round tiem < half last round time, increase difficulty
        if (this_round_time < last_round_time/2):
            return block['difficulty'] + 1
        return block['difficulty']

    # Query data
    def get_data(self, index):

        with self.conn.cursor() as cursor:
            try:
                # Perform MySQL query operations
                cursor.execute('select * from tb_blcokchain '
                               'where index=%s', (index,))
                result_sql = cursor.fetchall()
                print(result_sql)

                return result_sql
            except Exception as error:
                print(error)
            finally:
                self.conn.close()

    def post_data(self, block):
        with blockchain.conn.cursor() as cursor:
            try:
                # Insert the SQL statement, and result is the returned result
                res_info = cursor.execute(
                    'insert into tb_blockchain values %d, %s, %s, %s,%s, %d, %d',
                    (block['index'], block['transactions'], block['timestamp'], block['previous_hash'],
                     block['current_hash'],
                     block['difficulty'], block['proof']));

                # A successful insert requires a commit to synchronize in the database
                if isinstance(res_info, int):
                    print('数据更新成功')
                    blockchain.conn.commit()
            finally:
                # After the operation is complete, you need to close the connection
                blockchain.conn.close()

    def connect_to_db(self):
        """ Establishes connection with redis """
        r = redis.Redis(host=self.hostname,
                        port=self.portnumber,
                        password=self.password)
        try:
            r.ping()
        except redis.ConnectionError:
            sys.exit('ConnectionError: is the redis-server running?')
        self.r = r

    def ingest_to_db_stream(self, data):
        """ Args:
            data (string)
        """
        self.r.rpush('stream', json.dumps(data))

    def pull_and_store_stream(self, b):
        # Check if the blockchain is full
        for data in b.stream_from(full_blocks=True):
            self.ingest_to_db_stream(data)

app = Flask(__name__)

# 为节点创建一个随机名称
node_identifier = str(uuid4()).replace('-', '')

blockchain = Blockchain()


# 发送数据
@app.route('/transactions/new', methods=['POST'])
def new_transaction():

    values = request.get_json()
    required = ['sender', 'recipient', 'amount']
    if not all(k in values for k in required):
        return 'Missing values', 400  # 400 请求错误

    index = blockchain.new_transaction(values['sender'], values['recipient'], values['amount'])
    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201

def sign(sk, message):
    signature = sk.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature

def verify(pk, signature, message):
    # verify the signature using public key
    try:
        pk.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    except:  # occur some error
        return "false"
    else:  # no error
        return "true"

# 创建 /mine 端点，GET
@app.route('/mine', methods=['GET'])
def mine():

    last_block = blockchain.last_block
    last_proof = last_block['proof']
    last_difficulty = blockchain.change_difficulty(last_block);
    proof = blockchain.proof_of_work(last_proof, last_difficulty)

    blockchain.new_transaction(
        sender="0",
        recipient=node_identifier,
        amount=1,
    )

    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)
    block['difficulty'] = last_difficulty
    #current_hash = blockchain.hash(block)
    len0  = len(block['current_hash']) - len(block['current_hash'].lstrip('0'))
    block['current_hash'] = '0' * (block['difficulty']-len0) + block['current_hash']

    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'timestamp':block['timestamp'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
        'current_hash': block['current_hash'],
        'difficulty': block['difficulty']
    }

    return jsonify(response), 200


@app.route("/addneighbor",methods=['POST'])
def addNeighbor():
    node=request.values.get("node")
    if node==None:
        return "can not add",400
    if node not in blockchain.neighbor:
        blockchain.addNeighbor(node)
        response={
        "message":"successful",
    }
    else:
        response={
            "message":"already added"
        }
    for neighbor in blockchain.neighbor:
        print(neighbor)
    return jsonify(response),200


def blocktoJson(block):
    dir = {}
    dir['index'] = block['index']
    dir['timestamp'] = block['timestamp']
    dir['previous_hash'] = block['previous_hash']
    dir['current_hash'] = block['current_hash']
    dir['difficulty'] =block['difficulty']
    dir['proof'] = block['proof']
    dir['transactions'] = "".join('%s' %a for a in block['transactions'])
    return dir


@app.route("/getblocks",methods=['GET'])
def getBlocks():
    blocks=blockchain.chain
    chain=[]
    for block in blocks:
        chain.append(blocktoJson(block))
    response={
        'blocks':chain,
        'length':len(blocks),
        'message':'successful'
    }
    return jsonify(response),200


def handleBC(blocks: str):
    blockchain = []
    for temp in blocks.split('}')[:-1]:
        r1 = re.search("\"[\\w]+\":[\"]*.+[\"]*", temp)
        result = str(r1.group())
        print(result)
        result = '{' + result + '}'
        result_dir = eval(result)

        # TODO
        newBlock = {
            'index':result_dir['index'],
            'transactions' : handleTX(result_dir['transactions']),
            'timestamp' : result_dir['timestamp'],
            'previous_hash' : result_dir['previous_hash'],
            'current_hash': result_dir['current_hash'],
            'difficulty':result_dir['difficulty'],
            'proof' : result_dir['proof']
        }

        blockchain.append(newBlock)
    return blockchain

    #TODO 处理tx字符串
def handleTX(tx:str)->list:
    txlist=[]
    for temp in tx.split("}")[:-1]:
        r1=re.search("\'[a-z]+\': .+",temp)
        result=str(r1.group())
        result='{'+result+'}'
        result_dir=eval(result)
        txlist.append(str(result_dir))
    return txlist


@app.route("/broadcast", methods=['POST'])
def broadcast():
    length = request.form.get("length")
    blocks = request.form.get("blocks")

    if blocks == None:
        return "no blocks", 400

    if int(length) > len(blockchain.chain):
        blockchain.chain = handleBC(blocks)

        # print(Node.blockchain)
    response = {
        'message': 'get the broadcast'
    }
    return jsonify(response), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200


# 创建 /chain 端点，返回整个Blockchain类
@app.route('/chain', methods=['GET'])
# 将返回本节点存储的区块链条的完整信息和长度信息。
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200



# 服务器运行端口 5000
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
    app.wsgi_app = ProxyFix(app.wsgi_app)
    app.run()
