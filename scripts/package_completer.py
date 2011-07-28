# Script that interactively guides the user to completing a package

import os, sys, math
from collections import defaultdict
from subprocess import call

CDE_ROOT = '/cde-root'

# returns a dict mapping extension name to frequency of occurrence
def get_extensions_histogram(filelst):
  ret = defaultdict(int)
  for f in filelst:
    # special handling for '.so' to find files like 'libXcomposite.so.1.0.0'
    if '.so.' in f:
      ret['.so'] += 1
    else:
      ret[os.path.splitext(f)[1]] += 1
  return ret

# returns True iff d1 is a child directory of d2
def is_child_dir(d1, d2):
  return d1.startswith(d2) and d1[len(d2)] == '/'


class DirEntry:
  pass


# returns cumulative number of files and cumulative number of
# sub-directories in the current directory d
def get_cum_num_files_subdirs(dirname):
  num_files = 0
  num_subdirs = 0
  for (dn, subdirs, files) in os.walk(dirname):
    num_files += len(files)
    num_subdirs += len(subdirs)
  return (num_files, num_subdirs)


# parses log output as a result of running 'cde -l'
def parse_log(log_fn):
  files = []
  for line in open(log_fn):
    line = line.strip()

    # keep only the FIRST occurrence of a particular file
    # (or not ... seems to work better if you actually keep ALL occurrences)
    #if line in files: continue

    files.append(line)

  dirs_set = set(f for f in files if os.path.isdir(f))
  files = [e for e in files if e not in dirs_set] # filter out dirs

  dirnames = [os.path.dirname(f) for f in files]

  # Key: dirname
  # Value: list of indices of where it appears in dirnames
  appearance_indices = defaultdict(list)

  max_index = len(dirnames) - 1

  for (i, d) in enumerate(dirnames):
    # append this normalized index to all parent directories as well:
    cur = d
    while cur != '/':
      appearance_indices[cur].append(float(i) / max_index)
      cur = os.path.dirname(cur)


  # calculate mean
  dirnames_and_scores = [(k, float(sum(v)) / len(v)) for (k,v) in appearance_indices.iteritems()]
  # calculate median
  #dirnames_and_scores = [(k, sorted(v)[len(v)/2]) for (k,v) in appearance_indices.iteritems()]

  dirnames_and_scores.sort(key = lambda e:e[1], reverse=True)

  return dict(dirnames_and_scores)


def run_cde2(package_dir, logfile):

  log_scores = parse_log(logfile)

  while True:
    dat = []

    for (dirname, subdirs, files) in os.walk(package_dir):
      if CDE_ROOT not in dirname: continue
      system_dir = dirname[dirname.find(CDE_ROOT) + len(CDE_ROOT):]
      if not system_dir: continue

      if not os.path.isdir(system_dir):
        print "WARNING:", system_dir, "is in package but not on system."

      d = DirEntry()

      d.name = dirname
      d.system_dirname = system_dir

      d.nesting_level = d.system_dirname.count('/')

      try:
        d.log_score = log_scores[d.system_dirname]
      except KeyError:
        d.log_score = 0

      d.cum_num_files, d.cum_num_subdirs = get_cum_num_files_subdirs(d.name)
      d.cum_num_system_files, d.cum_num_system_subdirs =  get_cum_num_files_subdirs(d.system_dirname)

      # sum of squares to calculate 'euclidian distance'
      d.cum_score = 0

      # file coverage:

      #try: d.cum_score += pow(float(d.cum_num_files) / float(d.cum_num_system_files), 2)
      #except ZeroDivisionError: pass
      # add by 1 to penalize small values:
      d.cum_score += pow(float(d.cum_num_files) / float(d.cum_num_system_files + 1), 2)

      # sub-directory coverage:

      #try: d.cum_score += pow(float(d.cum_num_subdirs) / float(d.cum_num_system_subdirs), 2)
      #except ZeroDivisionError: pass
      # add by 1 to penalize small values:
      d.cum_score += pow(float(d.cum_num_subdirs) / float(d.cum_num_system_subdirs + 1), 2)

      # mean normalized occurrence order:
      d.cum_score += pow(d.log_score, 2)

      dat.append(d)

    dat.sort(key = lambda d: d.cum_score, reverse=True)

    # filter all completely-empty and completely-full directories
    dat = [d for d in dat if d.cum_num_files > 0 and d.cum_num_files < d.cum_num_system_files]

    # optional filter ... filter all sub-directories with LOWER scores
    # than their parents ... wow, this seems to be REALLY useful :)
    filtered_dat = []
    for d in dat:
      reject = False
      for fd in filtered_dat:
        if is_child_dir(d.system_dirname, fd.system_dirname):
          reject = True
          break

      if reject:
        #print 'REJECTED:', d.system_dirname, 'due to', fd.system_dirname
        pass
      else:
        filtered_dat.append(d)

    dat = filtered_dat

    for (i, d) in enumerate(dat):
      #if i >= 20: break
      print i + 1, ')', d.system_dirname, round(d.cum_score, 3), \
            '- %d/%d files,' % (d.cum_num_files, d.cum_num_system_files), \
            '%d/%d subdirs' % (d.cum_num_subdirs, d.cum_num_system_subdirs), \
            'lscore:', round(d.log_score, 3)

    print
    print "Choose sub-directory to copy into package ('q' to quit):",
    choice = raw_input()
    if choice == 'q':
      return
    else:
      choice = int(choice) - 1 # so we can be one-indexed for user-friendliness
    selected = dat[choice]

    # remember to put a trailing '/' to get rsync to work properly
    #
    # TODO: a problem with rsync is that if directories contain symlinks
    # to absolute paths, the symlinks won't be properly re-written to
    # point to the proper versions within cde-package/cde-root/
    #
    # see the code for create_symlink_in_cde_root() in cde.c for subtle
    # details about how to copy symlinks into cde-package/cde-root/
    #
    # also look into 'man rsync' for these options, which might help:
    #
    # -l, --links                 copy symlinks as symlinks
    # -L, --copy-links            transform symlink into referent file/dir
    #     --copy-unsafe-links     only "unsafe" symlinks are transformed
    #     --safe-links            ignore symlinks that point outside the tree
    # -k, --copy-dirlinks         transform symlink to dir into referent dir
    # -K, --keep-dirlinks         treat symlinked dir on receiver as dir
    #
    args = ['rsync', '-a', selected.system_dirname + '/', selected.name + '/']
    print args
    ret = call(args)
    assert ret == 0


# hard-code some test cases:
if __name__ == "__main__":
  if sys.argv[1] == 'abiword':
    pkg_name = 'abiword-package'
    logfile = 'cde-tests/abiword-copied-files.log'
  elif sys.argv[1] == 'chrome':
    pkg_name = 'chrome-package'
    logfile = 'cde-tests/chrome-copied-files.log'
  elif sys.argv[1] == 'firefox':
    pkg_name = 'firefox-package'
    logfile = 'cde-tests/firefox-copied-files.log'
  elif sys.argv[1] == 'sudoku':
    pkg_name = 'gnome-sudoku-package'
    logfile = 'cde-tests/sudoku-copied-files.log'
  elif sys.argv[1] == 'googleearth':
    pkg_name = 'googleearth-package'
    logfile = 'cde-tests/googleearth-copied-files.log'
  elif sys.argv[1] == 'gimp':
    pkg_name = 'gimp-package'
    logfile = 'cde-tests/gimp-copied-files.log'
  else:
    assert False
  
  call(['rm', '-rf', pkg_name + '/'])
  call(['tar', '-xf', 'cde-tests/%s.tar' % pkg_name])

  run_cde2(pkg_name, logfile)

  call(['rm', '-rf', pkg_name + '/']) # clean-up

