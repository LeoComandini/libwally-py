from setuptools import setup, find_packages

from pywally import __version__


setup(
    name='pywally',
    version=__version__,
    description='Pythonic wrapper of libwally',
    python_requires='>=3.6.0',
    url='https://github.com/LeoComandini/libwally-py',
    packages=find_packages(exclude=['tests']),
    install_requires=['wallycore>=0.7.4'],
    classifiers=[
        'Development Status :: 1 - Planning',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3 :: Only',
    ],
)
