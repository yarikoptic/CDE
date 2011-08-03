#include "paths.h"
#include <stdio.h>

int main(int argc, char** argv) {
  if (argc != 4) {
    fprintf(stderr, "Error: okapi takes exactly 3 arguments\n");
    return -1;
  }
  else {
    if (!IS_ABSPATH(argv[1])) {
      fprintf(stderr, "Error: '%s' is NOT an absolute path\n", argv[1]);
      return -1;
    }
    // argv[2] can be ""
    if ((strlen(argv[2]) > 0) && !IS_ABSPATH(argv[2])) {
      fprintf(stderr, "Error: '%s' is NOT an absolute path\n", argv[2]);
      return -1;
    }
    if (!IS_ABSPATH(argv[3])) {
      fprintf(stderr, "Error: '%s' is NOT an absolute path\n", argv[3]);
      return -1;
    }

    create_mirror_file(argv[1], argv[2], argv[3]);
  }
  return 0;
}
