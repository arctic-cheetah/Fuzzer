from setuptools import find_packages, setup
from Cython.Build import cythonize

# This program is an example of how to cythonise a python file.
# setup(ext_modules=cythonize("file_type.pyx"))
setup(
    py_modules=["file_type"],
    ext_modules=cythonize("file_type.py"),
    packages=find_packages("src"),
)
