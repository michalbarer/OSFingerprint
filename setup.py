from setuptools import setup, find_packages

setup(
    name='os_fingerprint',
    version='0.1.0',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'click',
        'scapy',
        'more_itertools',
        'pandas',
        'tabulate',
        'emoji'
    ],
    entry_points={
        'console_scripts': [
            'osfp = src.run_osfp:os_fingerprint',
        ],
    },
)