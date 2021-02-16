import traceback
import sys
import hashlib
import logging
import re

from sawtooth_sdk.processor.handler import TransactionHandler
from sawtooth_sdk.processor.exceptions import InvalidTransaction
from sawtooth_sdk.processor.exceptions import InternalError
from sawtooth_sdk.processor.core import TransactionProcessor

LOGGER = logging.getLogger(__name__)

FAMILY_NAME = "simplewallet"


def _hash(data):
    '''Compute the SHA-512 hash and return the result as hex characters.'''
    return hashlib.sha512(data).hexdigest()

# Prefix for simplewallet is the first six hex digits of SHA-512(TF name).
sw_namespace = _hash(FAMILY_NAME.encode('utf-8'))[0:6]


class FakeTransactionHandler(TransactionHandler):
    '''                                                       
    Transaction Processor class for the fake transaction family.       
                                                              
    This with the validator using the accept/get/set functions.
    It implements functions to add, buy, show, rm, sign and validate products.
    '''

    def __init__(self, namespace_prefix):
        self._namespace_prefix = namespace_prefix


    @property
    def family_name(self):
        return FAMILY_NAME

    @property
    def family_versions(self):
        return ['1.0']

    @property
    def namespaces(self):
        return [self._namespace_prefix]


    def apply(self, transaction, context):
        
        '''This implements the apply function for this transaction handler.
                                                              
           This function does most of the work for this class by processing
           a single transaction for the fake transaction family.   
        '''                                                   
        
        # Get the payload and extract fake-specific information.
        header = transaction.header
        payload_list = transaction.payload.decode().split(",")
        operation = payload_list[0]

        # Get the public key sent from the client.
        from_key = header.signer_public_key

        # Perform the operation.
        LOGGER.info("Operation = "+ operation)

        if operation == "add":
            product_id = payload_list[1]
            product_name = payload_list[2]
            self._make_add(context, product_id, product_name, from_key)
        elif operation == "sign":
            product_id = payload_list[1]
            product_name = payload_list[2]
            sig = payload_list[3]
            self._make_sign(context, product_id, product_name, sig, from_key)
        elif operation == "buy":
            product_id = payload_list[1]
            product_name = payload_list[2]
            self._make_buy(context, product_id, product_name, from_key)
        else:
            LOGGER.info("Unhandled action. " +
                "Operation should be add\\ show\\ buy\\ rm\\ sign\\ validate.")


    def _make_add(self, context, product_id, product_name, from_key):
        client_address = self._get_client_address(from_key)
        LOGGER.info('Got the key {} and the client address {} '.format(
            from_key, client_address))
        current_entry = context.get_state([client_address])
        
        if current_entry == []:
             LOGGER.info('No previous products, creating new product list {} '
                 .format(from_key))
             products = ["{}:{}:!".format(product_id, product_name)]
        else:
            products = current_entry[0].data.decode("utf-8").split(",")
            products.append("{}:{}:!".format(product_id, product_name))
        
        state_data = str(products).strip('[]').replace("'","").replace("''","").replace(" ","")    
        LOGGER.info("state_data:")
        LOGGER.info(state_data)
        state_data = bytes(state_data, 'utf-8')
        addresses = context.set_state({client_address: state_data})
        if len(addresses) < 1:
            raise InternalError("State Error")


    def _make_sign(self, context, product_id, product_name, sig, from_key):
        client_address = self._get_client_address(from_key)
        current_entry = context.get_state([client_address])
        
        if current_entry == []:
             LOGGER.info('No product to sign. {}' .format(from_key))
             raise InvalidTransaction('No product to sign.')
        else:
            products = current_entry[0].data.decode("utf-8")
            regex = "( ?{}:{}:".format(product_id, product_name)
            regex += "[a-f0-9A-F]{0,}!)"
            product = re.search(regex, products)
            try:
                product = product.group()
            except:
                LOGGER.info('Product does not exist.')
                raise InvalidTransaction('Product does not exist.')
            
            if product != "{}:{}:!".format(product_id, product_name) and product != " {}:{}:!".format(product_id, product_name):
                LOGGER.info('Product is already signed.')
                raise InvalidTransaction('Product is already signed.')
            else:
                new_prod = "{}:{}:{}!".format(product_id, product_name, str(sig))
                products = products.split(",")
                products[products.index(product)] = new_prod
                state_data = str(products).strip('[]').replace("'","").replace("''","")    
                state_data = bytes(state_data, 'utf-8')
                addresses = context.set_state({client_address: state_data})
   

    def _make_buy(self, context, product_id, product_name, key):
        address = self._get_client_address(key)
        LOGGER.info('Got key {} of address {} '.format(
            key, address))
        
        current_entry = context.get_state([address])
        if current_entry == []:
            raise InvalidTransaction('Product does not exist')

        products = current_entry[0].data.decode("utf-8")
        regex = "( ?{}:{}:".format(product_id, product_name)
        regex += "[a-f0-9A-F]{0,}!)"
        product = re.search(regex, products)
        try:
            product = product.group()
        except:
            LOGGER.info('Product does not exist.')
            raise InvalidTransaction('You cannot buy a product from someone that does not have it')
        
        products = products.split(",")
        products.remove(product)
        state_data = str(products).strip('[]').strip("'").replace("'","").replace("''","") 
        state_data = bytes(state_data, 'utf-8')
        context.set_state({address: state_data})


    def _get_client_address(self, from_key):
        return _hash(FAMILY_NAME.encode('utf-8'))[0:6] + _hash(from_key.encode('utf-8'))[0:64]


def setup_loggers():
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)


def main():
    '''Entry-point function for the simplewallet transaction processor.'''
    setup_loggers()
    try:
        # Register the transaction handler and start it.
        processor = TransactionProcessor(url='tcp://validator:4004')
        handler = FakeTransactionHandler(sw_namespace)
        processor.add_handler(handler)
        processor.start()

    except KeyboardInterrupt:
        pass
    except SystemExit as err:
        raise err
    except BaseException as err:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

