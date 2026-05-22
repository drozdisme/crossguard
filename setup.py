from setuptools import setup, find_packages
setup(
    name="crossguard",
    version="0.1.0-poc",
    description="Cross-layer security analyzer for Starknet bridge contracts",
    packages=find_packages(exclude=["tests*", "fixtures*"]),
    python_requires=">=3.11",
    install_requires=["pycryptodome>=3.19.0"],
    entry_points={"console_scripts": ["crossguard=crossguard.cli:main"]},
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Programming Language :: Python :: 3.11",
    ],
)
