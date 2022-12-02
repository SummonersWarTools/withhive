from setuptools import find_packages, setup

setup(
    name='withhive',
    packages=find_packages(include=['withhive']),
    version='0.1.0',
    description='Python binding for Com2Us Hive API.',
    author='ziddia',
    license='MIT',
    install_requires=['pycryptodome'],
    setup_requires=['pytest-runner'],
    tests_require=['pytest==4.4.1'],
    test_suite='tests',
)