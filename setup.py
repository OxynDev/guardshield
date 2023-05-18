import setuptools

setuptools.setup(
    name="excersec",
    version="1.0.0",
    author="Oxyn",
    author_email="oxyn.dev@gmail.com",
    description="Security lib",
    packages=setuptools.find_packages(),
    include_package_data = True,
    package_data = {
        'static': ['*'],
        'templates': ['*'],
        '':['*.dll'],
        '':['*']
    },
    zip_safe=False,
    license='MIT',

)