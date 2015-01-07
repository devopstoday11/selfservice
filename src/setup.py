try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages

from linotpselfservice import __version__

setup(
    name='LinOTPSelfservice',
    version=__version__,
    description='',
    author='',
    author_email='',
    url='',
    install_requires=[
        "Pylons>=1.0",
    ],
    setup_requires=["PasteScript>=1.6.3"],
    packages=find_packages(exclude=['ez_setup']),
    include_package_data=True,
    test_suite='nose.collector',
    package_data={'linotpselfservice': ['i18n/*/LC_MESSAGES/*.mo']},
    message_extractors={'linotpselfservice': [
            ('**.py', 'python', None),
            ('templates/**.mako', 'mako', {'input_encoding': 'utf-8'}),
            ('public/js/tools.js', 'javascript', {'input_encoding': 'utf-8'}),
            ('public/js/linotpselfservice.js', 'javascript', {'input_encoding': 'utf-8'}),
            ('public/js/linotp_utils.js', 'javascript', {'input_encoding': 'utf-8'}),
            ('public/**', 'ignore', None)]},
    zip_safe=False,
    paster_plugins=['PasteScript', 'Pylons'],
    entry_points="""
    [paste.app_factory]
    main = linotpselfservice.config.middleware:make_app

    [paste.app_install]
    main = pylons.util:PylonsInstaller
    """,
)
