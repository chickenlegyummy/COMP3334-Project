from setuptools import setup, find_packages

setup(
    name="secure_file_sharing",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "cryptography>=3.4",
    ],
    author="Bobby Li",
    description="3334 Project"
)