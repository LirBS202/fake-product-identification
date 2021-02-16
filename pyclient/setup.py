import os
import subprocess

from setuptools import setup, find_packages

data_files = []

setup(
    name='simplewallet-cli',
    version='1.0',
    description='Sawtooth SimpleWallet Example',
    author='askmish',
    url='https://github.com/askmish/sawtooth-simplewallet',
    packages=find_packages(),
    install_requires=[
        'aiohttp',
        'colorlog',
        'protobuf',
        'sawtooth-sdk',
        'sawtooth-signing',
        'PyYAML',
    ],
    data_files=data_files,
    entry_points={
        'console_scripts': [
            'fakep = fake_cli:main_wrapper',
        ]
    })

