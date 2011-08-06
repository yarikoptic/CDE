# Copy an entire directory (argv[1]) into (argv[2] + 'cde-root/')
# ---
#
# Use okapi to copy over all sub-directories and symlinks, and to make
# sure that all symlinks are properly munged to refer to relative paths
# within the package.  (Note that rsync does NOT munge symlinks!)
#
# by Philip Guo

import os, sys, subprocess

def run_cmd_print_stderr(args):
  (cmd_stdout, cmd_stderr) = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
  cmd_stderr = cmd_stderr.strip()
  if cmd_stderr:
    print cmd_stderr


script_dir = os.path.dirname(os.path.realpath(sys.argv[0]))
OKAPI_BIN = os.path.normpath(os.path.join(script_dir, "../okapi"))
assert os.path.isfile(OKAPI_BIN)


def copy_dir_into_package(basedir, package_root_dir):
  assert os.path.isdir(basedir)

  for (d, subdirs, files) in os.walk(basedir):
    # first copy over the directory so that it exists even if it's empty:
    run_cmd_print_stderr([OKAPI_BIN, d, '', package_root_dir])

    # now copy over all the files
    for f in files:
      p = os.path.join(d, f)
      run_cmd_print_stderr([OKAPI_BIN, p, '', package_root_dir])

    # if any subdirs are symlinks, then copy them over as well to
    # preserve the original directory/symlink structure:
    for sd in subdirs:
      p = os.path.join(d, sd)
      if os.path.islink(p):
        run_cmd_print_stderr([OKAPI_BIN, p, '', package_root_dir])


if __name__ == "__main__":
  package_root_dir = os.path.join(sys.argv[2], 'cde-root/')
  assert os.path.isdir(package_root_dir)
  copy_dir_into_package(sys.argv[1], package_root_dir)
