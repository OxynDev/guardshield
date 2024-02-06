import setuptools, os

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setuptools.setup(
    name="guardshield",
    version="1.1.6",
    author="Oxyn",
    author_email="oxyn.dev@gmail.com",
    description="Security lib",
    keywords = "python anti debugger security exe",
    packages=setuptools.find_packages(),
    package_data={'guardshield': ['utils/*']},
    include_package_data=True,
    url='https://github.com/OxynDev/guardshield',
    zip_safe=False,
    license='MIT',
    long_description=read('README.md'),
    long_description_content_type='text/markdown'
)