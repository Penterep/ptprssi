import setuptools
from ptprssi._version import __version__

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="ptprssi",
    version=__version__,
    description="Path-relative style sheet import testing tool",
    author="Penterep",
    author_email="info@penterep.com",
    url="https://www.penterep.com/",
    license="GPLv3+",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: Implementation :: CPython",
        "Environment :: Console",
        "Topic :: Security",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)"
    ],
    python_requires='>=3.6',
    install_requires=["ptlibs>=1,<2", "requests", "lxml", "bs4"],
    entry_points = {'console_scripts': ['ptprssi = ptprssi.ptprssi:main']},
    long_description=long_description,
    long_description_content_type="text/markdown",
)