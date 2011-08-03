#include "paths.h"
#include <stdio.h>

int main(int argc, char** argv) {
  if (argc != 4) {
    fprintf(stderr, "Error: okapi takes exactly 3 arguments\n");
    return -1;
  }
  else {
    create_mirror_file(argv[1], argv[2], argv[3]);
  }
  return 0;
}
