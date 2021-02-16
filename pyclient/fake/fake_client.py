import hashlib
import base64
import random
import requests
from random import randint
import yaml

from sawtooth_signing import create_context
from sawtooth_signing import CryptoFactory
from sawtooth_signing import ParseError
from sawtooth_signing.secp256k1 import Secp256k1PrivateKey
from sawtooth_signing.secp256k1 import Secp256k1Context

from sawtooth_sdk.protobuf.transaction_pb2 import TransactionHeader
from sawtooth_sdk.protobuf.transaction_pb2 import Transaction
from sawtooth_sdk.protobuf.batch_pb2 import BatchList
from sawtooth_sdk.protobuf.batch_pb2 import BatchHeader
from sawtooth_sdk.protobuf.batch_pb2 import Batch

# The Transaction Family Name
FAMILY_NAME = 'simplewallet'

def _hash(data):
    return hashlib.sha512(data).hexdigest()


class FakeClient(object):
    '''Client fake product identification class.

    This supports add, buy, sign, show, rm, verify products functions.
    '''

    def __init__(self, baseUrl, keyFile=None):
        '''Initialize the client class.

           This is mainly getting the key pair and computing the address.
        '''

        self._baseUrl = baseUrl

        if keyFile is None:
            self._signer = None
            return

        try:
            with open(keyFile) as fd:
                privateKeyStr = fd.read().strip()
        except OSError as err:
            raise Exception('Failed to read private key {}: {}'.format(
                keyFile, str(err)))

        try:
            privateKey = Secp256k1PrivateKey.from_hex(privateKeyStr)
        except ParseError as err:
            raise Exception('Failed to load private key: {}'.format(str(err)))

        self._signer = CryptoFactory(create_context('secp256k1')) \
            .new_signer(privateKey)

        self._publicKey = self._signer.get_public_key().as_hex()

        self._address = _hash(FAMILY_NAME.encode('utf-8'))[0:6] + \
            _hash(self._publicKey.encode('utf-8'))[0:64]


    def add(self, product_id, product_name):
        return self._wrap_and_send(
            "add", product_id, product_name)


    def sign(self, product_id, product_name):
        sig = self._signer.sign("{}:{}".format(product_id, product_name).encode('utf-8'))
        return self._wrap_and_send(
            "sign", product_id, product_name, sig)


    def fake_sign(self, product_id, product_name):
        sig = self._signer.sign("{}:{}".format(product_id, product_name).encode('utf-8'))
        fake_sig = ''.join(["{}".format(randint(0, 9)) for num in range(0, len(sig))])
        return self._wrap_and_send(
            "sign", product_id, product_name, fake_sig)


    def verify(self, product_id, product_name, signature):
        msg = bytes("{}:{}".format(product_id, product_name), 'utf-8')
        return Secp256k1Context().verify(signature, msg, self._signer.get_public_key())
 

    def remove(self, product_id, product_name, clientKey):
        try:
            with open(clientKey) as fd:
                publicKeyFromStr = fd.read().strip()
            retValue = self._wrap_and_send(
                "rm",
                product_id,
                product_name,
                clientKey)
        except Exception:
            raise Exception('Encountered an error during remove command')
        return retValue

    def transfer(self, product_id, product_name, clientKey):
        try:
            with open(clientKey) as fd:
                publicKeyStr = fd.read().strip()
            
            retValue = self._wrap_and_send(
                "buy",
                product_id,
                product_name,
                publicKeyStr)
        except OSError as err:
            raise Exception('Failed to read public key {}: {}'.format(
                clientToKey, str(err)))
        except Exception as err:
            raise Exception('Encountered an error during transfer', err)
        return retValue

    def show(self):
        result = self._send_to_restapi(
            "state/{}".format(self._address))
        try:
            return base64.b64decode(yaml.safe_load(result)["data"])

        except BaseException:
            return None

    def _send_to_restapi(self,
                         suffix,
                         data=None,
                         contentType=None):
        '''Send a REST command to the Validator via the REST API.'''

        if self._baseUrl.startswith("http://"):
            url = "{}/{}".format(self._baseUrl, suffix)
        else:
            url = "http://{}/{}".format(self._baseUrl, suffix)

        headers = {}

        if contentType is not None:
            headers['Content-Type'] = contentType

        try:
            if data is not None:
                result = requests.post(url, headers=headers, data=data)
            else:
                result = requests.get(url, headers=headers)

            if not result.ok:
                raise Exception("Error {}: {}".format(
                    result.status_code, result.reason))

        except requests.ConnectionError as err:
            raise Exception(
                'Failed to connect to {}: {}'.format(url, str(err)))

        except BaseException as err:
            raise Exception(err)

        return result.text


    def _wrap_and_send(self,
                       action,
                       *values):
        '''Create a transaction, then wrap it in a batch.     
                                                              
           Even single transactions must be wrapped into a batch.
        ''' 

        # Generate a csv utf-8 encoded string as payload
        rawPayload = action

        for val in values:
            rawPayload = ",".join([rawPayload, str(val)])

        payload = rawPayload.encode()

        # Construct the address where we'll store our state
        address = self._address
        inputAddressList = [address]
        outputAddressList = [address]

        if "buy" == action:
            toAddress = _hash(FAMILY_NAME.encode('utf-8'))[0:6] + \
            _hash(values[1].encode('utf-8'))[0:64]
            inputAddressList.append(toAddress)
            outputAddressList.append(toAddress)

        # Create a TransactionHeader
        header = TransactionHeader(
            signer_public_key=self._publicKey,
            family_name=FAMILY_NAME,
            family_version="1.0",
            inputs=inputAddressList,
            outputs=outputAddressList,
            dependencies=[],
            payload_sha512=_hash(payload),
            batcher_public_key=self._publicKey,
            nonce=random.random().hex().encode()
        ).SerializeToString()

        # Create a Transaction from the header and payload above
        transaction = Transaction(
            header=header,
            payload=payload,
            header_signature=self._signer.sign(header)
        )

        transactionList = [transaction]

        # Create a BatchHeader from transactionList above
        header = BatchHeader(
            signer_public_key=self._publicKey,
            transaction_ids=[txn.header_signature for txn in transactionList]
        ).SerializeToString()

        #Create Batch using the BatchHeader and transactionList above
        batch = Batch(
            header=header,
            transactions=transactionList,
            header_signature=self._signer.sign(header))

        #Create a Batch List from Batch above
        batch_list = BatchList(batches=[batch])

        # Send batch_list to rest-api
        return self._send_to_restapi(
            "batches",
            batch_list.SerializeToString(),
            'application/octet-stream')

