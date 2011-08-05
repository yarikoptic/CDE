# Copy all shared libraries referenced by constant strings within ELF binaries
# within the package root directory, argv[1] + 'cde-root/'
# ---
#
# Use 'file' to find all ELF binaries within the package, then use 'strings' to
# grep through all ELF binaries looking for "[.]so" patterns that are indicative
# of shared libraries, then use 'locate' to find those shared libraries on the
# system, then use 'okapi' to copy those libraries into the package root
# directory.  Repeat until the set of ELF binaries within the package converges.
#
# by Philip Guo

import os, sys, subprocess


def run_cmd(args):
  (cmd_stdout, cmd_stderr) = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
  return (cmd_stdout, cmd_stderr)


script_dir = os.path.dirname(os.path.realpath(sys.argv[0]))
OKAPI_BIN = os.path.normpath(os.path.join(script_dir, "../okapi"))
assert os.path.isfile(OKAPI_BIN)

PACKAGE_ROOT_DIR = os.path.join(sys.argv[1], 'cde-root/')
assert os.path.isdir(PACKAGE_ROOT_DIR)


# optimization to prevent unnecessary calls to 'locate', which are SLOW
already_seen_set = set()

i = 1
while True:
  print "Iteration:", i

  ELF_files_in_pkg = set()

  for (d, subdirs, files) in os.walk(PACKAGE_ROOT_DIR):
    for f in files:
        p = os.path.join(d, f)
        # file $p | grep "ELF "
        (file_cmd_stdout, _) = run_cmd(['file', p])
        if "ELF " in file_cmd_stdout:
          ELF_files_in_pkg.add(p)


  possible_libs_set = set()

  for f in ELF_files_in_pkg:
    # strings $f | grep "[.]so"
    (strings_cmd_stdout, _) = run_cmd(['strings', f])
    for s in strings_cmd_stdout.splitlines():
      if ".so" in s:
        possible_libs_set.add(s)


  libfiles_to_copy = set()

  for possible_lib in possible_libs_set:
    # optimization
    if possible_lib in already_seen_set:
      #print "Already seen:", possible_lib
      continue

    already_seen_set.add(possible_lib)
    # if it's an absolute path, use it as-is:
    if possible_lib[0] == '/':
      if os.path.isfile(possible_lib):
        libfiles_to_copy.add(possible_lib)
    # otherwise run 'locate' to find the library
    else:
      (locate_cmd_stdout, _) = run_cmd(['locate', possible_lib])
      for libfile in locate_cmd_stdout.splitlines():
        # only find EXACT basename matches with possible_lib
        if os.path.isfile(libfile) and os.path.basename(libfile) == possible_lib:
          libfiles_to_copy.add(libfile)

  files_to_remove = set()
  # check to see what's already in PACKAGE_ROOT_DIR:
  for f in libfiles_to_copy:
    assert f[0] == '/' # abspath!
    file_in_package = PACKAGE_ROOT_DIR + '/' + f
    if os.path.exists(file_in_package):
      files_to_remove.add(f)

  libfiles_to_copy -= files_to_remove

  for f in libfiles_to_copy:
    print "okapi-ing", f
    (okapi_stdout, okapi_stderr) = run_cmd([OKAPI_BIN, f, '', PACKAGE_ROOT_DIR])
    err = okapi_stderr.strip()
    if err:
      print err

  # exit condition
  if len(libfiles_to_copy) == 0:
    break

  i += 1
