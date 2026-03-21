from setuptools import setup, find_packages

setup(
    name="codesentinel",
    version="1.0.0",
    description="Autonomous Security Vulnerability Scanner",
    author="CodeSentinel",
    packages=find_packages(),
    install_requires=["colorama>=0.4.6", "pyyaml>=5.4"],
    python_requires=">=3.10",
    entry_points={
        "console_scripts": ["codesentinel=codesentinel.cli:main"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Environment :: Console",
    ],
)
