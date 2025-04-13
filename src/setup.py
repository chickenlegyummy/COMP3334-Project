from setuptools import setup, find_packages

setup(
    name="secure_file_sharing",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "cryptography>=3.4",
    ],
    author="LI Kwan To, LI Chun Fung, HO Cheuk Ting, WAN Ka Ho",
    description="COMP3334 Project"
)
