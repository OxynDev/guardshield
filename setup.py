import setuptools

setuptools.setup(
    name="guardshield",
    version="1.0.0",
    author="Oxyn",
    author_email="oxyn.dev@gmail.com",
    description="Security lib",
    packages=setuptools.find_packages(),
    include_package_data=True,
    url='https://github.com/OxynDev/ExcerSec',
    zip_safe=False,
    license='MIT',
    package_data={
        'guardshield': ['lib.dll'], 
    },
    data_files=[('guardshield', ['guardshield/lib.dll'])],
)