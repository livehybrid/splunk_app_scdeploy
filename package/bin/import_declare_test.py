import os
import sys
import re
from os.path import dirname

ta_name = 'splunk_app_scdeploy'
pattern = re.compile(r'[\\/]etc[\\/]apps[\\/][^\\/]+[\\/]bin[\\/]?$')
new_paths = [path for path in sys.path if not pattern.search(path) or ta_name in path]
new_paths.insert(0, os.path.join(dirname(dirname(__file__)), "lib"))
new_paths.insert(0, os.path.sep.join([os.path.dirname(__file__), ta_name]))
sys.path = new_paths

bindir = os.path.dirname(os.path.realpath(os.path.dirname(__file__)))
libdir = os.path.join(bindir, "lib")
platform = sys.platform
python_version = "".join(str(x) for x in sys.version_info[:2])

# Native wheels (cffi, pynacl) are vendored per interpreter by ucc-gen under
# lib/3rdparty/linux/<arch>/python<XY> (see os-dependentLibraries in
# globalConfig.json). Pick the directory for the running interpreter, so the
# same package works on Splunk 10.0/10.1 (Python 3.9) and 10.2+ (Python 3.13).
if platform.startswith("linux"):
	import platform as platform_module
	architecture = platform_module.machine()
	pydir = "python" + python_version
	if architecture in ("x86_64", "amd64"):
		sys.path.insert(0, os.path.join(libdir, "3rdparty", "linux", "x86_64", pydir))
	elif architecture in ("aarch64", "arm64"):
		sys.path.insert(0, os.path.join(libdir, "3rdparty", "linux", "aarch64", pydir))
	else:
		# Fallback: try both paths if architecture is unknown
		sys.path.insert(0, os.path.join(libdir, "3rdparty", "linux", "x86_64", pydir))
		sys.path.insert(0, os.path.join(libdir, "3rdparty", "linux", "aarch64", pydir))
