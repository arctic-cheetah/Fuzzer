from setuptools import find_packages, setup
from Cython.Build import cythonize

# This program is an example of how to cythonise a python file.
# setup(ext_modules=cythonize("file_type.pyx"))
# Run this from app directory: python3 src/cythonise.py  build_ext --inplac
setup(
    py_modules=["file_type"],
    ext_modules=cythonize("src/file_type.py"),
    packages=find_packages("src"),
)
