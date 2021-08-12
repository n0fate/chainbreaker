import codecs

from setuptools import setup, find_packages

dependencies = [
    'argparse',
    'pycryptodome',
]

setup(
    name='chainbreaker',
    version='2021.08.02',
    author='n0fate',
    author_email=codecs.encode('80008322+TvatreTrarfgr@hfref.abercyl.tvguho.pbz', 'rot-13'),
    license='GPL-2.0',
    url='https://github.com/GingerGeneste/chainbreaker',
    description='Extract information from OSX keychain files',
    #packages = find_packages(),
    classifiers=[
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    py_modules=["chainbreaker", "schema", "results", "logging_config", "args_control"],
    package_dir={'' : 'chainbreaker'}

)
