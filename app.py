import hashlib
import json
from datetime import datetime
import pymysql
import pymysql
from pymysql.converters import escape_string
import time
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
portval = 5000

# Create a random name for the receiver
node_identifier = str(uuid4()).replace('-', '')

sql = """
CREATE TABLE tb_blockchain(
id INT NOT NULL PRIMARY KEY,
transactions VARCHAR(255) NOT NULL,
timestamp VARCHAR(255) NOT NULL,
previous_hash VARCHAR(255) NOT NULL,
current_hash VARCHAR(255) NOT NULL, 
difficulty INT NOT NULL,
proof INT NOT NULL
);
"""

class Blockchain(object):

    def __init__(self):
        self.chain = []
        self.currentTransaction = []
        self.nodes = set()  # Store all node information in the blockchain network
        # Create the genesis block
        self.blockk = self.new_block(proof=100, previous_hash=1)
        self.neighbor = []


        try:
            self.conn = pymysql.connect(host='localhost', port=3306,
                                        user='root', password='123456',
                                        database='mysql', charset='utf8')
            # cursor = self.conn.cursor()
            # cursor.execute(sql)
            # cursor.close()
            # self.conn.close()
        except Exception as error:
            print('There is a problem connecting to MySQL！')
            print('Reason for failure：', error)
            exit()

        self.hostname = 'localhost'
        self.portnumber = 6379
        self.password = '654321'
        self.last_id = 0
        self.r = None

    # def addNeighbor(self, neighborr):
    #     self.neighbor.append(neighborr)

    def broadcastBC(self):
        myChain = []
        # print("self.chain:"+str(self.chain))
        for block in self.chain:
            myChain.append(block)

        data = {
            'blocks': str(myChain),
            'length': len(myChain)
        }
        for node in self.nodes:
            if node != int(portval):
                response = requests.post(f'http://127.0.0.1:{node}/broadcast', data=data)
                if response.status_code == 200:
                    print('广播成功')
                else:
                    print('广播失败')

    def blocktoJson(block):
        dir = {}
        dir["id"] = block['id']
        dir["transactions"] = block['transactions']
        dir["timestamp"] = block['timestamp']
        dir["previous_hash"] = block['previous_hash']
        dir["current_hash"] = block['current_hash']
        dir["difficulty"] = block['difficulty']
        dir["proof"] = block['proof']
        dir["merkle_root"] = block['merkle_root']

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
        current_id = 1

        while current_id < len(chain):
            block = chain[current_id]
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
            current_id += 1

        return True

    def new_transaction(self, sender, recipient, amount):

        gen = ecdsa.NIST256p.generator
        order = gen.order()
        # Generate private key d_ A
        d_A = random.randrange(1, order - 1)
        # Generate public and private key objects
        public_key = ecdsa.ecdsa.Public_key(gen, gen * d_A)
        private_key = ecdsa.ecdsa.Private_key(public_key, d_A)
        message = sender
        m = int(hashlib.sha1(message.encode("utf8")).hexdigest(), 16)
        # Temporary Key
        k = random.randrange(1, order - 1)
        signature = private_key.sign(m,k)

        if amount == 6.25:
            signature = ''

        txsID = hashlib.sha256(str(sender+recipient+str(amount))
                .encode())\
                .hexdigest()

        count_others = 0
        count_sql = """\
        select count(*) from tb_blockchain_{nodes}
            """
        for node in self.nodes:
            if node != int(portval):
                with self.conn.cursor() as cursor:
                    cursor.execute(count_sql.format(nodes=str(node)))
                    cnt = cursor.fetchone()[0]
                    self.conn.commit()
                    count_others += cnt

         # After 51% attack, double spending happened
        if len(self.chain) > count_others:
            print("double spending happens!")


        self.currentTransaction.append({
            'transactionID': txsID,
            'transactionInput':signature,
            'transactionOutput':{
                'recipient':recipient,
                'amount':amount
            }
        })

        if len(self.chain) == 0:
            return 1
        return self.last_block['id'] + 1


    def new_block(self, proof, previous_hash=None):

        idx = len(self.chain) + 1
        t = hashlib.sha256(" ".join('%s' %a for a in self.currentTransaction).encode('utf-8')).hexdigest()
        i = hashlib.sha256(str(idx).encode('utf-8')).hexdigest()
        ts = hashlib.sha256(datetime.now().strftime("%m%d%Y%H%M%S").encode('utf-8')).hexdigest()
        ph = hashlib.sha256(str(previous_hash).encode('utf-8')).hexdigest()
        p = hashlib.sha256(str(proof).encode('utf-8')).hexdigest()
        crt_hash = hashlib.sha256(str(t + i + ts + ph + p).encode('utf-8')).hexdigest()
        merkle = t

        if int(portval) != 5000:
            time.sleep(3)

        if len(self.currentTransaction) == 0:
            self.new_transaction(
                sender="0",
                recipient="rrrrrr",
                amount=6.25
            )

        block = {
            'id': (len(self.chain) + 1),
            'transactions': str(self.currentTransaction),
            'timestamp': time.time(),
            'previous_hash': str(previous_hash or self.hash(self.chain[-1])),
            'current_hash': str(crt_hash),
            'difficulty': 4,
            'proof': proof,
            'merkle_root':merkle
        }
        if block['id'] == 1:
            block['current_hash'] = '0' * block['difficulty'] + block['current_hash']

        self.currentTransaction = []
        self.chain.append(block)
        return block




    @staticmethod
    def hash(block):
        return block['current_hash']

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
        # if this round time < half last round time, increase difficulty
        if (this_round_time < last_round_time/2):
            return block['difficulty'] + 1
        return block['difficulty']

    # Query data
    def get_data(self, number):

        with self.conn.cursor() as cursor:
            try:
                # Perform MySQL query operations
                # select_sql = "SELECT * FROM tb_blockchain where id = %s"

                # SELECT * FROM tb_blockchain
                # WHERE id='{idx}'

                cursor.execute("SELECT * FROM tb_blockchain where id = %s", str(number))

                result_sql = cursor.fetchall()

                print(result_sql)

                return result_sql
            except Exception as error:
                print(error)
            # finally:
            #     self.conn.close()

    def post_data(self, block):
        with self.conn.cursor() as cursor:
            # try:
                # Insert the SQL statement, and result is the returned result

                insert_sql = """\
                    INSERT INTO tb_blockchain VALUES ('{current_hash}', '{difficulty}', '{id}' ,'{previous_hash}', '{proof}', '{timestamp}', '{transactions}', '{merkle_root}')
                """

                res_info = cursor.execute(
                    insert_sql.format(node=str(portval), current_hash=str(block['current_hash']), difficulty=block['difficulty'], id=block['id'],
                                      previous_hash=block['previous_hash'], proof=block['proof'], timestamp=str(block['timestamp']),
                                      transactions=escape_string((block['transactions'])), merkle_root=str(block['merkle_root']) )
                    # sql ,
                    # [str(block['current_hash']), block['difficulty'], block['id'], str(block['previous_hash']),
                    #  block['proof'], str(block['timestamp']), str(block['transactions'])
                    #     ]
                    # ['qqq', 5, 2,'www',7,'34562.44','fgghhyg']


                # A successful insert requires a commit to synchronize in the database
                if isinstance(res_info, int):
                    self.conn.commit()
            # finally:
            #     # After the operation is complete, you need to close the connection
            #     blockchain.conn.close()

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

    def ingest_to_db_stream(self, chainheight, fullnode, utxolist):
        """ Args:
            data (string)
        """
        # self.r.rpush('stream1', json.dumps(chainheight))
        self.r.set('stream1', str(chainheight))
        self.r.set('stream2', str(fullnode))
        self.r.set('stream3', str(utxolist))


app = Flask(__name__)

blockchain = Blockchain()

blockchain.connect_to_db()

blockchain.ingest_to_db_stream(len(blockchain.chain),blockchain.nodes, blockchain.currentTransaction)


valueslist = []

def strtoJson(tx:str)->dict:
    temp  = tx.split('&')
    return {
        'sender': temp[0].split('=')[1],
        'recipient':temp[1].split('=')[1],
        'amount':temp[2].split('=')[1]
    }

@app.route('/transactions/new', methods=['POST'])
def new_transaction():

    values = request.get_json()
    if type(values) != dict:
        valueslist = strtoJson(values)
    else:
        valueslist = values

    required = ['sender', 'recipient', 'amount']
    if not all(k in valueslist for k in required):
        return 'Missing values', 400

    id = blockchain.new_transaction(valueslist['sender'], valueslist['recipient'], valueslist['amount'])

    # print("valueslist:"+str(valueslist))
    response = {'message': f'Transaction will be added to Block {id}'}

    return jsonify(response), 201

def sign(sk, message):
    signature = sk.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature

def verify(pk, signature, message):
    # verify the signature using public key
    try:
        verify(signature, message, ec.ECDSA(hashes.SHA256()))
    except:  # occur some error
        return "false"
    else:  # no error
        return "true"

@app.route('/mine', methods=['GET'])
def mine():

    count = 0
    while True:
        last_block = blockchain.last_block
        last_proof = last_block['proof']
        last_difficulty = blockchain.change_difficulty(last_block)
        proof = last_proof + 1

        previous_hash = blockchain.hash(last_block)
        block = blockchain.new_block(proof, previous_hash)
        block['difficulty'] = last_difficulty

        diff = block['difficulty']
        hash1 = block['current_hash']
        while True:
            hash2 = hashlib.sha256((str(proof) + str(hash1)).encode('utf-8')).hexdigest()
            zerobits = ['0'] * diff
            if (hash2[:diff] == ''.join(zerobits)):
                break
            proof += 1
        block['current_hash'] = hash2
        block['proof'] = proof

        blockchain.post_data(block)

        blockchain.ingest_to_db_stream(len(blockchain.chain), blockchain.nodes, blockchain.currentTransaction)

        count += 1
        if count == 200:
            blockchain.broadcastBC()
            count = 0


        blockdict = {
            'id': block['id'],
            'transactions': block['transactions'],
            'timestamp': block['timestamp'],
            'proof': block['proof'],
            'previous_hash': block['previous_hash'],
            'current_hash': block['current_hash'],
            'difficulty': block['difficulty'],
            'merkle_root': block['merkle_root']
        }
        # print(blockdict)

        response = {
            'message': "New Block Forged",
            'block':blockdict,
        }

    return jsonify(response), 200


def blocktoJson(block):
    dir = {}
    dir['id'] = block['id']
    dir['timestamp'] = block['timestamp']
    dir['previous_hash'] = block['previous_hash']
    dir['current_hash'] = block['current_hash']
    dir['difficulty'] =block['difficulty']
    dir['proof'] = block['proof']
    dir['transactions'] = "".join('%s' %a for a in block['transactions'])
    dir['merkle_root'] = block['merkle_root']
    return dir


@app.route("/getblocks",methods=['GET'])
def getBlocks():
    blocks=blockchain.chain

    # blockchain.get_data(1)

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
    block_chain = []
    # print("blocks:"+str(blocks))


    block_list = ast.literal_eval(blocks)
    for block in block_list:
        block_dict = eval(str(block))
        newBlock = {
            'id':block_dict['id'],
            'transactions': block_dict['transactions'],
            'timestamp' : block_dict['timestamp'],
            'previous_hash' : block_dict['previous_hash'],
            'current_hash': block_dict['current_hash'],
            'difficulty':block_dict['difficulty'],
            'proof' : block_dict['proof'],
            'merkle_root':block_dict['merkle_root']
        }
        print("222")
        print("handleBC:"+str(newBlock))
        blockchain.append(newBlock)

    return block_chain

def handleTX(tx:str)->list:
    txlist=[]
    if len(tx) > 2:
        tx_list = ast.literal_eval(tx)
        for temp in tx_list:
            tx_dict = eval(str(temp))
            txlist.append(str(tx_dict))
    return txlist


@app.route("/broadcast", methods=['POST'])
def broadcast():
    length = request.form.get("length")
    blocks = request.form.get("blocks")

    if blocks == None:
        return "no blocks", 400


    if int(length) >= len(blockchain.chain):
        # blockchain.valid_chain(blockchain.chain)
        # print("broadcast-handleBC")
        blockchain.chain = handleBC(blocks)

    # print(blockchain.chain)

    response = {
        'message': 'get the broadcast'
    }
    return jsonify(response), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()

    nodes = values.split('=')[1]
    if nodes not in blockchain.nodes:
        blockchain.nodes.add(nodes)

    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    blockchain.register_node(nodes)


    total_nodes = []
    for node in blockchain.nodes:
        nodedict = {}
        nodedict['node'] = node
        total_nodes.append(nodedict)
    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201

# return Blockchain
@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200

if __name__ == '__main__':

    portval = input('Please input the number of node:')
    app.run(host='127.0.0.1', port=int(portval))
    app.wsgi_app = ProxyFix(app.wsgi_app)
    app.run()
