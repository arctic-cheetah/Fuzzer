from setuptools import setup
from Cython.Build import cythonize

# This program is an example of how to cythonise a python file.
# setup(ext_modules=cythonize("file_type.pyx"))
setup(ext_modules=cythonize("file_type.py"))
