from setuptools import setup, find_packages

setup(
    name='os_fingerprint',
    version='0.1.0',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'click',
        'scapy'
    ],
    entry_points={
        'console_scripts': [
            'osfp = src.cli:os_fingerprint',
        ],
    },
)