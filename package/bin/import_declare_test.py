import os
import sys
import re
from os.path import dirname
import platform

ta_name = 'splunk_app_scdeploy'
pattern = re.compile(r'[\\/]etc[\\/]apps[\\/][^\\/]+[\\/]bin[\\/]?$')
new_paths = [path for path in sys.path if not pattern.search(path) or ta_name in path]
new_paths.insert(0, os.path.join(dirname(dirname(__file__)), "lib"))
new_paths.insert(0, os.path.sep.join([os.path.dirname(__file__), ta_name]))
sys.path = new_paths

bindir = os.path.dirname(os.path.realpath(os.path.dirname(__file__)))
libdir = os.path.join(bindir, "lib")
python_version = sys.version_info
if platform.system()=="linux":
    architecture = platform.machine()
    #3rdparty/linux/x86_64/python39
	sys.path.insert(0, os.path.join(libdir, f"3rdparty/linux/{architecture}/python{python_version.major}{python_version.minor}"))
    # Architectures
    # arm64
    # x86_64
    # aarch64