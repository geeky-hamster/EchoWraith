from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("VERSION", "r", encoding="utf-8") as fh:
    version = fh.read().strip()

setup(
    name="echowraith",
    version=version,
    author="Your Name",
    author_email="your.email@example.com",
    description="Advanced WiFi Security Analysis Platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/echowraith",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires=">=3.6",
    install_requires=[
        "rich>=13.7.0",
        "scapy>=2.5.0",
        "netifaces>=0.11.0",
        "cryptography>=41.0.0",
        "pyroute2>=0.7.9",
        "netaddr>=0.8.0",
        "prompt_toolkit>=3.0.43",
        "pycryptodomex>=3.19.0",
        "rf-security-toolkit>=1.2.0",
        "wireless-framework>=2.1.0",
        "network-proto-analyzer>=1.0.3",
    ],
    entry_points={
        "console_scripts": [
            "echowraith=echowraith.main:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
) 