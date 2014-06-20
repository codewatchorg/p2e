from distutils.core import setup
import py2exe
import sys
import os

setup(
	options = {'py2exe': {'bundle_files': 1}},
	zipfile = None,
	console=['p2e.py']
)