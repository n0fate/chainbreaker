import codecs

from setuptools import setup, find_packages

dependencies = [
    'argparse',
    'pycryptodome',
]

setup(
    name='chainbreaker',
    version='3.0.0',
    author='n0fate',
    author_email=codecs.encode('80008322+TvatreTrarfgr@hfref.abercyl.tvguho.pbz', 'rot-13'),
    license='GPL-2.0',
    url='https://github.com/GingerGeneste/chainbreaker',
    description='Extract information from OSX keychain files',
    packages=find_packages(exclude=['tests']),
    classifiers=[
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    install_requires=dependencies,
)
