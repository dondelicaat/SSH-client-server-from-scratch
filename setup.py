from setuptools import setup, find_packages

setup(
   name='ssh',
   packages=find_packages('src'),
   package_dir={'': 'src'},
   install_requires=[
      'pycrypto'
   ]
)
