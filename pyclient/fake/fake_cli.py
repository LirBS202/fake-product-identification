import argparse
import logging
import os
import sys
import traceback
import json
import pkg_resources
import urllib.request
import re
from colorlog import ColoredFormatter
from fake.fake_client import FakeClient

DISTRIBUTION_NAME = 'simplewallet'
DEFAULT_URL = 'http://rest-api:8008'
URL = 'http://rest-api:8008/blocks'


def create_console_handler(verbose_level):
    clog = logging.StreamHandler()
    formatter = ColoredFormatter(
        "%(log_color)s[%(asctime)s %(levelname)-8s%(module)s]%(reset)s "
        "%(white)s%(message)s",
        datefmt="%H:%M:%S",
        reset=True,
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red',
        })

    clog.setFormatter(formatter)
    clog.setLevel(logging.DEBUG)
    return clog


def setup_loggers(verbose_level):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(create_console_handler(verbose_level))


def add_add_parser(subparsers, parent_parser):
    '''Define the "add" command line parsing.'''
    parser = subparsers.add_parser(
        'add',
        help='adds a new product to a client',
        parents=[parent_parser])

    parser.add_argument(
        'product_name',
        type=str,
        help='the product name')

    parser.add_argument(
        'customerName',
        type=str,
        help='the name of customer to add the product to')


def add_sign_parser(subparsers, parent_parser):
    '''Define the "sign" command line parsing.'''
    parser = subparsers.add_parser(
        'sign',
        help='signs a product',
        parents=[parent_parser])
    
    parser.add_argument(
        'product_id',
        type=int,
        help='product identification number')

    parser.add_argument(
        'product_name',
        type=str,
        help='the product name')

    parser.add_argument(
        'customerName',
        type=str,
        help='the name of customer to sign the product.')


def add_fake_sign_parser(subparsers, parent_parser):
    '''Define the "fake_sign" command line parsing.'''
    parser = subparsers.add_parser(
        'fake_sign',
        help='signs a fake signiture.',
        parents=[parent_parser])
    
    parser.add_argument(
        'product_id',
        type=int,
        help='product identification number')

    parser.add_argument(
        'product_name',
        type=str,
        help='the product name')

    parser.add_argument(
        'customerName',
        type=str,
        help='the name of customer to sign the product.')


def add_verify_parser(subparsers, parent_parser):
    '''Define the "verify" command line parsing.'''
    parser = subparsers.add_parser(
        'verify',
        help='verifies product digital signiture.',
        parents=[parent_parser])
    
    parser.add_argument(
        'product_id',
        type=int,
        help='product identification number')

    parser.add_argument(
        'product_name',
        type=str,
        help='the product name')

    parser.add_argument(
        'sellerName',
        type=str,
        help='Sellers name')

    parser.add_argument(
        'signiture',
        type=str,
        help='the product signiture')


def add_remove_parser(subparsers, parent_parser):
    '''Define the "remove" command line parsing.'''
    parser = subparsers.add_parser(
        'rm',
        help='removes a product from the sellers products list',
        parents=[parent_parser])

    parser.add_argument(
        'product_id',
        type=int,
        help='product identification number')

    parser.add_argument(
        'product_name',
        type=str,
        help='product name')

    parser.add_argument(
        'customerName',
        type=str,
        help='the name of seller to remove item from')


def add_show_parser(subparsers, parent_parser):
    '''Define the "show" command line parsing.'''
    parser = subparsers.add_parser(
        'show',
        help='shows your products',
        parents=[parent_parser])

    parser.add_argument(
        'customerName',
        type=str,
        help='the name of customer')


def add_buy_parser(subparsers, parent_parser):
    '''Define the "buy" command line parsing.'''
    parser = subparsers.add_parser(
        'buy',
        help='buy a product',
        parents=[parent_parser])

    parser.add_argument(
        'product_id',
        type=int,
        help='product identification number')

    parser.add_argument(
        'product_name',
        type=str,
        help='product name')

    parser.add_argument(
        'customerNameFrom',
        type=str,
        help='the name of customer to buy from')

    parser.add_argument(
        'customerName',
        type=str,
        help='the name of customer who buys the product')


def create_parent_parser(prog_name):
    '''Define the -V/--version command line options.'''
    parent_parser = argparse.ArgumentParser(prog=prog_name, add_help=False)

    try:
        version = pkg_resources.get_distribution(DISTRIBUTION_NAME).version
    except pkg_resources.DistributionNotFound:
        version = 'UNKNOWN'

    parent_parser.add_argument(
        '-V', '--version',
        action='version',
        version=(DISTRIBUTION_NAME + ' (Hyperledger Sawtooth) version {}')
        .format(version),
        help='display version information')

    return parent_parser


def create_parser(prog_name):
    '''Define the command line parsing for all the options and subcommands.'''
    parent_parser = create_parent_parser(prog_name)

    parser = argparse.ArgumentParser(
        description='Provides subcommands to manage your simple wallet',
        parents=[parent_parser])

    subparsers = parser.add_subparsers(title='subcommands', dest='command')
    subparsers.required = True

    add_add_parser(subparsers, parent_parser)
    add_remove_parser(subparsers, parent_parser)
    add_show_parser(subparsers, parent_parser)
    add_buy_parser(subparsers, parent_parser)
    add_sign_parser(subparsers, parent_parser)
    add_fake_sign_parser(subparsers, parent_parser)
    add_verify_parser(subparsers, parent_parser)

    return parser


def _get_keyfile(customerName):
    '''Get the private key for a customer.'''
    home = os.path.expanduser("~")
    key_dir = os.path.join(home, ".sawtooth", "keys")
    return '{}/{}.priv'.format(key_dir, customerName)


def _get_pubkeyfile(customerName):
    '''Get the public key for a customer.'''
    home = os.path.expanduser("~")
    key_dir = os.path.join(home, ".sawtooth", "keys")

    return '{}/{}.pub'.format(key_dir, customerName)


def do_add(args, flag=False):
    '''Implements the "add" subcommand by calling the client class.'''
    if(flag):
        product_id = args.product_id
    else:
        with urllib.request.urlopen(URL) as resp:
            html = resp.read().decode("utf-8")
        res = re.findall('"block_num": "(\d)"', html)
        product_id = max(res)

    keyfile = _get_keyfile(args.customerName)
    client = FakeClient(baseUrl=DEFAULT_URL, keyFile=keyfile)
    response = client.add(product_id, args.product_name)
    print("Response: {}".format(response))


def do_sign(args):
    keyfile = _get_keyfile(args.customerName)
    client = FakeClient(baseUrl=DEFAULT_URL, keyFile=keyfile)
    response = client.sign(args.product_id, args.product_name)

    response_url = json.loads(response)['link']
    with urllib.request.urlopen(response_url) as resp:
        html = json.loads(resp.read())

    if(html['data'][0]['status'] == "INVALID"):
        print(html['data'][0]['invalid_transactions'][0]['message'])
    else:
        print("Response: {}".format(response))


def do_fake_sign(args):
    keyfile = _get_keyfile(args.customerName)
    client = FakeClient(baseUrl=DEFAULT_URL, keyFile=keyfile)
    response = client.fake_sign(args.product_id, args.product_name)

    response_url = json.loads(response)['link']
    with urllib.request.urlopen(response_url) as resp:
        html = json.loads(resp.read())

    if(html['data'][0]['status'] == "INVALID"):
        print(html['data'][0]['invalid_transactions'][0]['message'])
    else:
        print("Response: {}".format(response))


def do_verify(args):
    keyfile = _get_keyfile(args.sellerName)
    client = FakeClient(baseUrl=DEFAULT_URL, keyFile=keyfile)

    response = client.verify(args.product_id, args.product_name, args.signiture)
    if response:
        print("\nSigniture varified!")
    else:
        print("\nBad Signiture.. :(")


def do_remove(args):
    '''Implements the "remove" subcommand by calling the client class.'''
    keyfile = _get_keyfile(args.customerName)
    client = FakeClient(baseUrl=DEFAULT_URL, keyFile=keyfile)
    response = client.transfer(args.product_id, args.product_name, keyfile)

    response_url = json.loads(response)['link']
    with urllib.request.urlopen(response_url) as resp:
        html = json.loads(resp.read())

    if(html['data'][0]['status'] == "INVALID"):
        print(html['data'][0]['invalid_transactions'][0]['message'])
    else:
        print("Response: {}".format(response))


def do_show(args):
    '''Implements the "show" subcommand by calling the client class.'''
    keyfile = _get_keyfile(args.customerName)
    client = FakeClient(baseUrl=DEFAULT_URL, keyFile=keyfile)

    try:
        products = client.show().decode("utf-8").split(",")
    except:
        products = None

    if products not in [None, [] ,['']]:
        print("\n{} has the next products:\n".format(args.customerName))
        
        for product in products:
            product = product.replace("'","").replace("''","")
            pro_id, pro_name, sig = product.split(":")
            if sig != "!":
                print("Product id:  \t{}\nProduct name:".format(pro_id)
                    + "\t{}\nSigniture:\t{}\n".format(pro_name, sig))
            else:
                print("Product id:  \t{}\nProduct name:".format(pro_id)
                    + "\t{}\nNot Signed\n".format(pro_name))
    else:
        print("\n{} has no products\n".format(args.customerName))


def do_buy(args):
    '''Implements the "buy" subcommand by calling the client class.'''
    keyfile = _get_keyfile(args.customerNameFrom)
    client = FakeClient(baseUrl=DEFAULT_URL, keyFile=keyfile)
    response = client.transfer(args.product_id, args.product_name, keyfile)
    
    response_url = json.loads(response)['link']
    with urllib.request.urlopen(response_url) as resp:
        html = json.loads(resp.read())

    if(html['data'][0]['status'] == "INVALID"):
        print(html['data'][0]['invalid_transactions'][0]['message'])
    else:
        do_add(args, True)


def main(prog_name=os.path.basename(sys.argv[0]), args=None):
    '''Entry point function for the client CLI.'''
    if args is None:
        args = sys.argv[1:]
    parser = create_parser(prog_name)
    args = parser.parse_args(args)

    verbose_level = 0

    setup_loggers(verbose_level=verbose_level)

    # Get the commands from cli args and call corresponding handlers
    if args.command == 'add':
        do_add(args)
    elif args.command == 'rm':
        do_remove(args)
    elif args.command == 'sign':
        do_sign(args)
    elif args.command == "fake_sign":
        do_fake_sign(args)
    elif args.command == 'verify':
        do_verify(args)
    elif args.command == 'show':
        do_show(args)
    elif args.command == 'buy':
        if args.customerNameFrom == args.customerName:
            raise Exception("Cannot buy product from yourself: {}"
                                        .format(args.customerNameFrom))
        do_buy(args)
    else:
        raise Exception("Invalid command: {}".format(args.command))


def main_wrapper():
    try:
        main()
    except KeyboardInterrupt:
        pass
    except SystemExit as err:
        raise err
    except BaseException as err:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

