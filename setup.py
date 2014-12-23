from setuptools import setup, find_packages
import sys, os

version = '0.1'

setup(
    name='ckanext-dataset',
    version=version,
    description="modifikacia atributov datasetu",
    long_description='''
    ''',
    classifiers=[], # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
    keywords='',
    author='Dominik Kapisinsky',
    author_email='kapisinsky@microcomp.sk',
    url='edem.microcomp.sk',
    license='',
    packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
    namespace_packages=['ckanext', 'ckanext.dataset'],
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        # -*- Extra requirements: -*-
    ],
    entry_points={
        'babel.extractors': [
                'ckan = ckan.lib.extract:extract_ckan',
                ],
                'ckan.plugins' : [
                        'dataset=ckanext.dataset.plugin:ExtendedDatasetPlugin',
                ]
        }

    
)
