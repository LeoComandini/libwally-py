from setuptools import setup, find_packages
from distutils.util import convert_path

with open(convert_path('pywally/version.py')) as f:
    exec(f.read())

setup(
    name='pywally',
    version=__version__,
    description='Pythonic wrapper of libwally',
    python_requires='>=3.6.0',
    url='https://github.com/LeoComandini/libwally-py',
    packages=find_packages(exclude=['tests']),
    install_requires=['wallycore>=0.7.7'],
    classifiers=[
        'Development Status :: 1 - Planning',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3 :: Only',
    ],
)
