#!/usr/bin/env python
from setuptools import setup, find_packages

setup(name="python-instagram",
      version="1.1.3",
      description="Instagram API client",
      license="MIT",
      install_requires=["simplejson","httplib2", "requests", "pycurl", "lxml", "grab"],
      author="Instagram, Inc",
      author_email="apidevelopers@instagram.com",
      url="http://github.com/Instagram/python-instagram",
      packages = find_packages(),
      keywords= "instagram",
      zip_safe = True)
