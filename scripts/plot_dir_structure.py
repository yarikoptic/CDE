# traverses a directory tree and plots out the resulting directory
# structure to stdout in GraphViz .dot format

import os, sys, hashlib

basedir = os.path.realpath(sys.argv[1])
pwd = os.getcwd()

# Key:   node name ('node_' + md5-hash)
# Value: full path
already_rendered = {}

def get_node_name(path):
  return 'node_' + hashlib.md5(path).hexdigest()


def get_canonical_name(path):
  assert path.startswith(basedir)
  #return path[len(basedir):]
  return path.split('/')[-1]

print "digraph {"
print 'rankdir="LR"'

for (d, subdirs, files) in os.walk(basedir):
  dirnode = get_node_name(d)
  if dirnode not in already_rendered:
    print dirnode, '[label="%s", shape=box] /* %s */' % (get_canonical_name(d), d)
    already_rendered[dirnode] = d

  for f in files + subdirs:
    p = os.path.join(d, f)
    filenode = get_node_name(p)

    print '%s->%s' % (dirnode, filenode)

    if os.path.islink(p):
      target = os.path.realpath(os.path.join(d, os.readlink(p)))
      if filenode not in already_rendered:
        print filenode, '[label="%s", shape=diamond] /* %s */' % (get_canonical_name(p), p)
        already_rendered[filenode] = p

      print '%s->%s' % (filenode, get_node_name(target))
    else:
      if filenode not in already_rendered:
        already_rendered[filenode] = p
        if os.path.isfile(p):
          print filenode, '[label="%s", shape=ellipse] /* %s */' % (get_canonical_name(p), p)
        else:
          assert os.path.isdir(p)
          print filenode, '[label="%s", shape=box] /* %s */' % (get_canonical_name(p), p)

print "}"

