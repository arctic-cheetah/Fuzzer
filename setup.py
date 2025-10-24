from setuptools import setup
from Cython.Build import cythonize

# TODO: rewrite
# setup(ext_modules=cythonize("file_type.pyx"))
setup(ext_modules=cythonize("file_type.py"))
