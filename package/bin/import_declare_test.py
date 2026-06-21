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

if python_version == "39":
	if platform.startswith("linux"):
		import platform as platform_module
		architecture = platform_module.machine()
		# Map common architecture names to our directory structure
		if architecture in ("x86_64", "amd64"):
			sys.path.insert(0, os.path.join(libdir, "3rdparty/linux/x86_64/python39"))
		elif architecture in ("aarch64", "arm64"):
			sys.path.insert(0, os.path.join(libdir, "3rdparty/linux/aarch64/python39"))
		else:
			# Fallback: try both paths if architecture is unknown
			sys.path.insert(0, os.path.join(libdir, "3rdparty/linux/x86_64/python39"))
			sys.path.insert(0, os.path.join(libdir, "3rdparty/linux/aarch64/python39"))

if python_version == "37":
	if platform.startswith("linux"):
		import platform as platform_module
		architecture = platform_module.machine()
		# Map common architecture names to our directory structure
		if architecture in ("x86_64", "amd64"):
			sys.path.insert(0, os.path.join(libdir, "3rdparty/linux/x86_64/python37"))
		elif architecture in ("aarch64", "arm64"):
			sys.path.insert(0, os.path.join(libdir, "3rdparty/linux/aarch64/python37"))
		else:
			# Fallback: try both paths if architecture is unknown
			sys.path.insert(0, os.path.join(libdir, "3rdparty/linux/x86_64/python37"))
			sys.path.insert(0, os.path.join(libdir, "3rdparty/linux/aarch64/python37"))
