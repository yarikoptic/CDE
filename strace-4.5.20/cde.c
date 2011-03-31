/* 

CDE: Code, Data, and Environment packaging for Linux
http://www.stanford.edu/~pgbovine/cde.html
Philip Guo

CDE is currently licensed under GPL v3:

  Copyright (c) 2010 Philip Guo <pg@cs.stanford.edu>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/


/* System call calling conventions:
  
   According to this page:
     http://stackoverflow.com/questions/2535989/what-are-the-calling-conventions-for-unix-linux-system-calls-on-x86-64

  32-bit x86:
    syscall number: %eax
    first 6 syscall parameters: %ebx, %ecx, %edx, %esi, %edi, %ebp

  64-bit x86-64:
    syscall number: %rax
    first 6 syscall parameters: %rdi, %rsi, %rdx, %rcx, %r8 and %r9

*/

#include "cde.h"
#include "paths.h"
#include <dirent.h>

// for CDE_begin_socket_bind_or_connect
#include <sys/socket.h>
#include <sys/un.h>


// TODO: eliminate this hack if it results in a compile-time error
#include "config.h" // to get I386 / X86_64 definitions
#if defined (I386)
__asm__(".symver shmctl,shmctl@GLIBC_2.0"); // hack to eliminate glibc 2.2 dependency
#endif


// 1 if we are executing code in a CDE package,
// 0 for tracing regular execution
char CDE_exec_mode;

char CDE_provenance_mode = 0; // -p option
char CDE_verbose_mode = 0; // -v option

static char cde_options_initialized = 0; // set to 1 after CDE_init_options() done

static void begin_setup_shmat(struct tcb* tcp);
static void* find_free_addr(int pid, int exec, unsigned long size);
static void find_and_copy_possible_dynload_libs(char* filename, char* child_current_pwd);

static char* strcpy_from_child(struct tcb* tcp, long addr);
static int ignore_path(char* filename);

#define SHARED_PAGE_SIZE (MAXPATHLEN * 4)

static char* redirect_filename_into_cderoot(char* filename, char* child_current_pwd);
static void memcpy_to_child(int pid, char* dst_child, char* src, int size);
static void create_symlink_in_cde_root(char* filename, char* child_current_pwd);

// the true pwd of the cde executable AT THE START of execution
char cde_starting_pwd[MAXPATHLEN];

// these arrays are initialized in CDE_init_options()
static char* ignore_exact_paths[100];
static char* ignore_prefix_paths[100];
static char* ignore_substr_paths[100];
int ignore_exact_paths_ind = 0;
int ignore_prefix_paths_ind = 0;
int ignore_substr_paths_ind = 0;

// these override their ignore path counterparts
static char* redirect_exact_paths[100];
static char* redirect_prefix_paths[100];
static char* redirect_substr_paths[100];
int redirect_exact_paths_ind = 0;
int redirect_prefix_paths_ind = 0;
int redirect_substr_paths_ind = 0;

static char* ignore_envvars[100]; // each element should be an environment variable to ignore
int ignore_envvars_ind = 0;


// the absolute path to the cde-root/ directory, since that will be
// where our fake filesystem starts. e.g., if cde_starting_pwd is
//   /home/bob/cde-package/cde-root/home/alice/cool-experiment
// then cde_pseudo_root_dir is:
//   /home/bob/cde-package/cde-root
//
// only relevant when we're executing in CDE_exec_mode
char cde_pseudo_root_dir[MAXPATHLEN];


// to shut up gcc warnings without going thru #include hell
extern ssize_t getline(char **lineptr, size_t *n, FILE *stream);

extern char* find_ELF_program_interpreter(char * file_name); // from ../readelf-mini/libreadelf-mini.a

extern void path_pop(struct path* p);


// returns a component within real_pwd that represents the part within
// cde_pseudo_root_dir
// the return value should NOT be mutated; otherwise we might be screwed!
static char* extract_sandboxed_pwd(char* real_pwd) {
  assert(CDE_exec_mode);

  // spoof getcwd by only taking the part BELOW cde-root/
  // e.g., if real_pwd is:
  //   /home/bob/cde-package/cde-root/home/alice/cool-experiment
  // then return:
  //   /home/alice/cool-experiment
  // as cwd
  int cde_pseudo_root_dir_len = strlen(cde_pseudo_root_dir);

  char real_pwd_is_within_cde_pseudo_root_dir =
    ((strlen(real_pwd) >= cde_pseudo_root_dir_len) &&
     (strncmp(real_pwd, cde_pseudo_root_dir, cde_pseudo_root_dir_len) == 0));

  // if real_pwd is within a strange directory like '/tmp' that should
  // be ignored, AND if it resides OUTSIDE of cde_pseudo_root_dir, then
  // simply return itself
  //
  // e.g., if real_pwd is '/tmp', then return itself,
  // but if real_pwd is '/tmp/cde-package/cde-root/home/pgbovine' and
  // cde_pseudo_root_dir is '/tmp/cde-package/cde-root/', then
  // treat it like any normal path (extract '/home/pgbovine')
  if (ignore_path(real_pwd) && !real_pwd_is_within_cde_pseudo_root_dir) {
    return real_pwd;
  }

  // sanity check, make sure real_pwd is within/ cde_pseudo_root_dir,
  // if we're not ignoring it
  if (!real_pwd_is_within_cde_pseudo_root_dir) {
    fprintf(stderr,
            "Fatal error: '%s' is outside of cde-root/ and NOT being ignored.\n",
            real_pwd);
    exit(1);
  }

  char* sandboxed_pwd = (real_pwd + cde_pseudo_root_dir_len);

  // special case for '/' directory:
  if (strlen(sandboxed_pwd) == 0) {
    return "/";
  }
  else {
    return sandboxed_pwd;
  }
}


// prepend $CDE_ROOT_DIR to the given path string, assumes that the string
// starts with '/' (i.e., it's an absolute path)
//
// warning - this returns a relative path
// mallocs a new string!
char* prepend_cderoot(char* path) {
  assert(IS_ABSPATH(path));
  char* ret = malloc(CDE_ROOT_LEN + strlen(path) + 1);
  strcpy(ret, CDE_ROOT_DIR);
  strcat(ret, path);
  return ret;
}

// WARNING: this function behaves differently depending on value of CDE_exec_mode
char* create_abspath_within_cderoot(char* path) {
  assert(IS_ABSPATH(path)); // Pre-req: path must be an absolute path!

  if (CDE_exec_mode) {
    // if we're making a cde-exec run, then simply re-route it
    // inside of cde_pseudo_root_dir
    return format("%s%s", cde_pseudo_root_dir, path);
  }
  else {
    // if we're making an ORIGINAL (tracing) run, then simply prepend
    // CDE_ROOT_DIR to path and canonicalize it
    char* relpath_within_cde_root = prepend_cderoot(path);

    // really really tricky ;)  if the child process has changed
    // directories, then we can't rely on relpath_within_cde_root to
    // exist.  instead, we must create an ABSOLUTE path based on
    // cde_starting_pwd, which is the directory where cde-exec was first launched!
    char* ret = canonicalize_relpath(relpath_within_cde_root, cde_starting_pwd);
    free(relpath_within_cde_root);

    assert(IS_ABSPATH(ret));
    return ret;
  }
}


// original_abspath must be an absolute path
// create all the corresponding 'mirror' directories within
// cde-package/cde-root/, MAKING SURE TO CREATE DIRECTORY SYMLINKS
// when necessary (sort of emulate "mkdir -p" functionality)
// if pop_one is non-zero, then pop last element before doing "mkdir -p"
static void make_mirror_dirs_in_cde_package(char* original_abspath, int pop_one) {
  // use a sneaky new_path_internal call so that we can accept relative
  // paths in fullpath
  struct path* p = new_path_from_abspath(original_abspath);

  if (pop_one) {
    path_pop(p); // e.g., ignore filename portion to leave just the dirname
  }

  int i;
  for (i = 1; i <= p->depth; i++) {
    char* dn = path2str(p, i);
    char* dn_within_package = prepend_cderoot(dn);

    // only do this if dn_within_package doesn't already exist
    // (to prevent possible infinite loops)
    struct stat already_exists_stat;
    if (lstat(dn_within_package, &already_exists_stat) != 0) {
      struct stat dn_stat;
      if (lstat(dn, &dn_stat) == 0) { // this does NOT follow the symlink
        char is_symlink = S_ISLNK(dn_stat.st_mode);
        if (is_symlink) {
          create_symlink_in_cde_root(dn, NULL);
        }
        else {
          assert(S_ISDIR(dn_stat.st_mode));
          mkdir(dn_within_package, 0777);
        }
      }
    }

    free(dn_within_package);
    free(dn);
  }
  delete_path(p);
}


// does simple string comparisons.  (e.g., if you want to compare
// with absolute paths, then filename had better be an absolute path!)
static int ignore_path(char* filename) {
  assert(cde_options_initialized);

  // sometimes you will get a BOGUS empty filename ... in that case,
  // simply ignore it (this might hide some true errors, though!!!)
  if (filename[0] == '\0') {
    return 1;
  }

  int i;

  // redirect paths override ignore paths
  for (i = 0; i < redirect_exact_paths_ind; i++) {
    if (strcmp(filename, redirect_exact_paths[i]) == 0) {
      return 0;
    }
  }
  for (i = 0; i < redirect_prefix_paths_ind; i++) {
    char* p = redirect_prefix_paths[i];
    if (strncmp(filename, p, strlen(p)) == 0) {
      return 0;
    }
  }
  for (i = 0; i < redirect_substr_paths_ind; i++) {
    if (strstr(filename, redirect_substr_paths[i])) {
      return 0;
    }
  }


  for (i = 0; i < ignore_exact_paths_ind; i++) {
    if (strcmp(filename, ignore_exact_paths[i]) == 0) {
      return 1;
    }
  }
  for (i = 0; i < ignore_prefix_paths_ind; i++) {
    char* p = ignore_prefix_paths[i];
    if (strncmp(filename, p, strlen(p)) == 0) {
      return 1;
    }
  }
  for (i = 0; i < ignore_substr_paths_ind; i++) {
    if (strstr(filename, ignore_substr_paths[i])) {
      return 1;
    }
  }


  // do NOT ignore by default.  if you want to ignore everything except
  // for what's explicitly specified by 'redirect' directives, then
  // use an option like "ignore_prefix=/" (to ignore everything) and
  // then add redirect_prefix= and redirect_exact= directives accordingly
  return 0;
}


// cp $src_filename $dst_filename
// note that this WILL follow symlinks
void copy_file(char* src_filename, char* dst_filename) {
  int inF;
  int outF;
  int bytes;
  char buf[4096]; // TODO: consider using BUFSIZ if it works better

  //printf("COPY %s %s\n", src_filename, dst_filename);

  // do a full-on copy
  EXITIF((inF = open(src_filename, O_RDONLY)) < 0);
  // create with permissive perms
  EXITIF((outF = open(dst_filename, O_WRONLY | O_CREAT, 0777)) < 0);

  while ((bytes = read(inF, buf, sizeof(buf))) > 0) {
    write(outF, buf, bytes);
  }
    
  close(inF);
  close(outF);
}

// this is the meaty and super-complicated function that copies a file
// into its respective location within cde-root/
//
// if filename is a symlink, then copy both it AND its target into cde-root
static void copy_file_into_cde_root(char* filename, char* child_current_pwd) {
  assert(filename);
  assert(!CDE_exec_mode);

  // resolve absolute path relative to child_current_pwd and
  // get rid of '..', '.', and other weird symbols
  char* filename_abspath = canonicalize_path(filename, child_current_pwd);

  // don't copy filename that we're ignoring (remember to use ABSOLUTE PATH)
  if (ignore_path(filename_abspath)) {
    free(filename_abspath);
    return;
  }

  char* dst_path = prepend_cderoot(filename_abspath);

  // this will NOT follow the symlink ...
  struct stat filename_stat;
  EXITIF(lstat(filename_abspath, &filename_stat));
  char is_symlink = S_ISLNK(filename_stat.st_mode);

  if (is_symlink) {
    // 'stat' will follow the symlink ...
    if (stat(filename_abspath, &filename_stat)) {
      // be failure-oblivious here
      fprintf(stderr, "CDE WARNING: target of '%s' symlink cannot be found\n", filename_abspath);
      goto done;
    }
  }

  // by now, filename_stat contains the info for the actual target file,
  // NOT a symlink to it

  if (S_ISREG(filename_stat.st_mode)) { // regular file or symlink to regular file
    // lazy optimization to avoid redundant copies ...
    struct stat dst_path_stat;
    if (stat(dst_path, &dst_path_stat) == 0) {
      // if the destination file exists and is newer than the original
      // filename, then don't do anything!
      if (dst_path_stat.st_mtime >= filename_stat.st_mtime) {
        //printf("PUNTED on %s\n", dst_path);
        goto done;
      }
    }
  }

  // finally, 'copy' filename_abspath over to dst_path

  // if it's a symlink, copy both it and its target
  if (is_symlink) {
    create_symlink_in_cde_root(filename, child_current_pwd);
  }
  else {
    if (S_ISREG(filename_stat.st_mode)) { // regular file
      // create all the directories leading up to it, to make sure file
      // copying/hard-linking will later succeed
      //mkdir_recursive(dst_path, 1);
      make_mirror_dirs_in_cde_package(filename_abspath, 1);

      // regular file, simple common case :)
      // 1.) try a hard link for efficiency
      // 2.) if that fails, then do a straight-up copy,
      //     but do NOT follow symlinks
      //
      // EEXIST means the file already exists, which isn't
      // really a hard link failure ...
      if ((link(filename_abspath, dst_path) != 0) && (errno != EEXIST)) {
        copy_file(filename_abspath, dst_path);
      }

      // if it's a shared library, then heuristically try to grep
      // through it to find whether it might dynamically load any other
      // libraries (e.g., those for other CPU types that we can't pick
      // up via strace)
      find_and_copy_possible_dynload_libs(filename_abspath, child_current_pwd);
    }
    else if (S_ISDIR(filename_stat.st_mode)) { // directory or symlink to directory
      // do a "mkdir -p filename" after redirecting it into cde-root/
      //mkdir_recursive(dst_path, 0);
      make_mirror_dirs_in_cde_package(filename_abspath, 0);
    }
  }

done:
  free(dst_path);
  free(filename_abspath);
}


#define STRING_ISGRAPHIC(c) ( ((c) == '\t' || (isascii (c) && isprint (c))) )

/* If filename is an ELF binary file, then do a binary grep through it
   looking for strings that might be '.so' files, as well as dlopen*,
   which is a function call to dynamically load an .so file.  Find
   whether any of the .so files exist in the same directory as filename,
   and if so, COPY them into cde-root/ as well.

   The purpose of this hack is to pick up on libraries for alternative
   CPU types that weren't picked up when running on this machine.  When
   the package is ported to another machine, the program might load one
   of these alternative libraries.
  
   Note that this heuristic might lead to false positives (incidental
   matches) and false negatives (cannot find dynamically-generated
   strings).  
  
   code adapted from the string program (strings.c) in GNU binutils */
static void find_and_copy_possible_dynload_libs(char* filename, char* child_current_pwd) {
  FILE* f = fopen(filename, "rb"); // open in binary mode
  if (!f) {
    return;
  }

  char header[5];
  memset(header, 0, sizeof(header));
  fgets(header, 5, f); // 5 means 4 bytes + 1 null terminating byte

  // if it's not even an ELF binary, then punt early for efficiency
  if (strcmp(header, "\177ELF") != 0) {
    //printf("Sorry, not ELF %s\n", filename);
    fclose(f);
    return;
  }

  int i;
  int dlopen_found = 0; // did we find a symbol starting with 'dlopen'?

  char cur_string[MAXPATHLEN];
  cur_string[0] = '\0';
  int cur_ind = 0;

  // it's unrealistic to expect more than 50, right???
  char* libs_to_check[50];
  int libs_to_check_ind = 0;

  while (1) {

    while (1) {
      int c = getc(f);
      if (c == EOF)
        goto done;
      if (!STRING_ISGRAPHIC(c))
        break;

      // don't overflow ... just truncate off of end
      if (cur_ind < sizeof(cur_string) - 1) {
        cur_string[cur_ind++] = c;
      }
    }

    // done with a string
    cur_string[cur_ind] = '\0';

    int cur_strlen = strlen(cur_string);

    // don't even bother for short strings:
    if (cur_strlen >= 4) {
      // check that it ends with '.so'
      if ((cur_string[cur_strlen - 3] == '.') &&
          (cur_string[cur_strlen - 2] == 's') &&
          (cur_string[cur_strlen - 1] == 'o')) {

        libs_to_check[libs_to_check_ind++] = strdup(cur_string);
        assert(libs_to_check_ind < 50); // bounds check
      }

      if (strncmp(cur_string, "dlopen", 6) == 0) {
        dlopen_found = 1;
      }
    }

    // reset buffer
    cur_string[0] = '\0';
    cur_ind = 0;
  }


done:
  // for efficiency and to prevent false positives,
  // only do filesystem checks if dlopen has been found
  if (dlopen_found) {
    char* filename_copy = strdup(filename); // dirname() destroys its arg
    char* dn = dirname(filename_copy);

    for (i = 0; i < libs_to_check_ind; i++) {
      char* lib_fullpath = format("%s/%s", dn, libs_to_check[i]);
      // if the target library exists, then copy it into our package
      struct stat st;
      if (stat(lib_fullpath, &st) == 0) {
        //printf("%s %s\n", filename, lib_fullpath);

        // this COULD recursively call
        // find_and_copy_possible_dynload_libs(), but it won't infinite
        // loop if we activate the optimization where we punt if the
        // file already exists and hasn't been updated:
        copy_file_into_cde_root(lib_fullpath, child_current_pwd);
      }
      free(lib_fullpath);
    }

    free(filename_copy);
  }


  for (i = 0; i < libs_to_check_ind; i++) {
    free(libs_to_check[i]);
  }

  fclose(f);
}


// modify a single argument to the given system call
// to a path within cde-root/, if applicable
//
// assumes tcp->opened_filename has already been set,
// which will be the filename that we are redirecting
//
// arg_num == 1 mean modify first register arg
// arg_num == 2 mean modify second register arg
static void modify_syscall_single_arg(struct tcb* tcp, int arg_num) {
  assert(CDE_exec_mode);
  assert(tcp->opened_filename);

  char* redirected_filename =
    redirect_filename_into_cderoot(tcp->opened_filename, tcp->current_dir);
  if (!redirected_filename) {
    return;
  }

  if (!tcp->childshm) {
    begin_setup_shmat(tcp);

    // no more need for filename, so don't leak it
    free(redirected_filename);
    free(tcp->opened_filename);
    tcp->opened_filename = NULL;

    return; // MUST punt early here!!!
  }

  //printf("  attempt to modify %s => %s\n", tcp->opened_filename, redirected_filename);

  // redirect all requests for absolute paths to version within cde-root/
  // if those files exist!

  strcpy(tcp->localshm, redirected_filename); // hopefully this doesn't overflow :0

  //printf("  redirect %s\n", tcp->localshm);
  //static char tmp[MAXPATHLEN];
  //EXITIF(umovestr(tcp, (long)tcp->childshm, sizeof tmp, tmp) < 0);
  //printf("     %s\n", tmp);

  struct user_regs_struct cur_regs;
  EXITIF(ptrace(PTRACE_GETREGS, tcp->pid, NULL, (long)&cur_regs) < 0);

  if (arg_num == 1) {
#if defined (I386)
    cur_regs.ebx = (long)tcp->childshm;
#elif defined(X86_64)
    cur_regs.rdi = (long)tcp->childshm;
#else
    #error "Unknown architecture (not I386 or X86_64)"
#endif
  }
  else {
    assert(arg_num == 2);
#if defined (I386)
    cur_regs.ecx = (long)tcp->childshm;
#elif defined(X86_64)
    cur_regs.rsi = (long)tcp->childshm;
#else
    #error "Unknown architecture (not I386 or X86_64)"
#endif
  }

  ptrace(PTRACE_SETREGS, tcp->pid, NULL, (long)&cur_regs);

  free(redirected_filename);
}


// copy and paste from modify_syscall_first_arg ;)
static void modify_syscall_two_args(struct tcb* tcp) {
  assert(CDE_exec_mode);

  if (!tcp->childshm) {
    begin_setup_shmat(tcp);
    return; // MUST punt early here!!!
  }

  char* filename1 = strcpy_from_child(tcp, tcp->u_arg[0]);
  char* redirected_filename1 =
    redirect_filename_into_cderoot(filename1, tcp->current_dir);
  free(filename1);

  char* filename2 = strcpy_from_child(tcp, tcp->u_arg[1]);
  char* redirected_filename2 =
    redirect_filename_into_cderoot(filename2, tcp->current_dir);
  free(filename2);

  // gotta do both, yuck
  if (redirected_filename1 && redirected_filename2) {
    strcpy(tcp->localshm, redirected_filename1);

    int len1 = strlen(redirected_filename1);
    char* redirect_file2_begin = ((char*)tcp->localshm) + len1 + 1;
    strcpy(redirect_file2_begin, redirected_filename2);

    struct user_regs_struct cur_regs;
    EXITIF(ptrace(PTRACE_GETREGS, tcp->pid, NULL, (long)&cur_regs) < 0);

#if defined (I386)
    cur_regs.ebx = (long)tcp->childshm;
    cur_regs.ecx = (long)(((char*)tcp->childshm) + len1 + 1);
#elif defined(X86_64)
    cur_regs.rdi = (long)tcp->childshm;
    cur_regs.rsi = (long)(((char*)tcp->childshm) + len1 + 1);
#else
  #error "Unknown architecture (not I386 or X86_64)"
#endif

    ptrace(PTRACE_SETREGS, tcp->pid, NULL, (long)&cur_regs);

    //static char tmp[MAXPATHLEN];
    //EXITIF(umovestr(tcp, (long)cur_regs.ebx, sizeof tmp, tmp) < 0);
    //printf("  ebx: %s\n", tmp);
    //EXITIF(umovestr(tcp, (long)cur_regs.ecx, sizeof tmp, tmp) < 0);
    //printf("  ecx: %s\n", tmp);
  }
  else if (redirected_filename1) {
    strcpy(tcp->localshm, redirected_filename1);

    struct user_regs_struct cur_regs;
    EXITIF(ptrace(PTRACE_GETREGS, tcp->pid, NULL, (long)&cur_regs) < 0);

#if defined (I386)
    cur_regs.ebx = (long)tcp->childshm; // only set EBX
#elif defined(X86_64)
    cur_regs.rdi = (long)tcp->childshm;
#else
  #error "Unknown architecture (not I386 or X86_64)"
#endif

    ptrace(PTRACE_SETREGS, tcp->pid, NULL, (long)&cur_regs);
  }
  else if (redirected_filename2) {
    strcpy(tcp->localshm, redirected_filename2);

    struct user_regs_struct cur_regs;
    EXITIF(ptrace(PTRACE_GETREGS, tcp->pid, NULL, (long)&cur_regs) < 0);

#if defined (I386)
    cur_regs.ecx = (long)tcp->childshm; // only set ECX
#elif defined(X86_64)
    cur_regs.rsi = (long)tcp->childshm;
#else
  #error "Unknown architecture (not I386 or X86_64)"
#endif

    ptrace(PTRACE_SETREGS, tcp->pid, NULL, (long)&cur_regs);
  }

  if (redirected_filename1) free(redirected_filename1);
  if (redirected_filename2) free(redirected_filename2);
}

// modify the second and fourth args to redirect into cde-root/
// really nasty copy-and-paste from modify_syscall_two_args above
static void modify_syscall_second_and_fourth_args(struct tcb* tcp) {
  assert(CDE_exec_mode);

  if (!tcp->childshm) {
    begin_setup_shmat(tcp);
    return; // MUST punt early here!!!
  }

  char* filename1 = strcpy_from_child(tcp, tcp->u_arg[1]);
  char* redirected_filename1 =
    redirect_filename_into_cderoot(filename1, tcp->current_dir);
  free(filename1);

  char* filename2 = strcpy_from_child(tcp, tcp->u_arg[3]);
  char* redirected_filename2 =
    redirect_filename_into_cderoot(filename2, tcp->current_dir);
  free(filename2);

  // gotta do both, yuck
  if (redirected_filename1 && redirected_filename2) {
    strcpy(tcp->localshm, redirected_filename1);

    int len1 = strlen(redirected_filename1);
    char* redirect_file2_begin = ((char*)tcp->localshm) + len1 + 1;
    strcpy(redirect_file2_begin, redirected_filename2);

    struct user_regs_struct cur_regs;
    EXITIF(ptrace(PTRACE_GETREGS, tcp->pid, NULL, (long)&cur_regs) < 0);

#if defined (I386)
    cur_regs.ecx = (long)tcp->childshm;
    cur_regs.esi = (long)(((char*)tcp->childshm) + len1 + 1);
#elif defined(X86_64)
    cur_regs.rsi = (long)tcp->childshm;
    cur_regs.rcx = (long)(((char*)tcp->childshm) + len1 + 1);
#else
  #error "Unknown architecture (not I386 or X86_64)"
#endif

    ptrace(PTRACE_SETREGS, tcp->pid, NULL, (long)&cur_regs);
  }
  else if (redirected_filename1) {
    strcpy(tcp->localshm, redirected_filename1);

    struct user_regs_struct cur_regs;
    EXITIF(ptrace(PTRACE_GETREGS, tcp->pid, NULL, (long)&cur_regs) < 0);

#if defined (I386)
    cur_regs.ecx = (long)tcp->childshm;
#elif defined(X86_64)
    cur_regs.rsi = (long)tcp->childshm;
#else
  #error "Unknown architecture (not I386 or X86_64)"
#endif

    ptrace(PTRACE_SETREGS, tcp->pid, NULL, (long)&cur_regs);
  }
  else if (redirected_filename2) {
    strcpy(tcp->localshm, redirected_filename2);

    struct user_regs_struct cur_regs;
    EXITIF(ptrace(PTRACE_GETREGS, tcp->pid, NULL, (long)&cur_regs) < 0);

#if defined (I386)
    cur_regs.esi = (long)tcp->childshm; // only set ECX
#elif defined(X86_64)
    cur_regs.rcx = (long)tcp->childshm;
#else
  #error "Unknown architecture (not I386 or X86_64)"
#endif

    ptrace(PTRACE_SETREGS, tcp->pid, NULL, (long)&cur_regs);
  }

  if (redirected_filename1) free(redirected_filename1);
  if (redirected_filename2) free(redirected_filename2);
}

// modify the first and third args to redirect into cde-root/
// really nasty copy-and-paste from modify_syscall_two_args above
static void modify_syscall_first_and_third_args(struct tcb* tcp) {
  assert(CDE_exec_mode);

  if (!tcp->childshm) {
    begin_setup_shmat(tcp);
    return; // MUST punt early here!!!
  }

  char* filename1 = strcpy_from_child(tcp, tcp->u_arg[0]);
  char* redirected_filename1 =
    redirect_filename_into_cderoot(filename1, tcp->current_dir);
  free(filename1);

  char* filename2 = strcpy_from_child(tcp, tcp->u_arg[2]);
  char* redirected_filename2 =
    redirect_filename_into_cderoot(filename2, tcp->current_dir);
  free(filename2);

  // gotta do both, yuck
  if (redirected_filename1 && redirected_filename2) {
    strcpy(tcp->localshm, redirected_filename1);

    int len1 = strlen(redirected_filename1);
    char* redirect_file2_begin = ((char*)tcp->localshm) + len1 + 1;
    strcpy(redirect_file2_begin, redirected_filename2);

    struct user_regs_struct cur_regs;
    EXITIF(ptrace(PTRACE_GETREGS, tcp->pid, NULL, (long)&cur_regs) < 0);

#if defined (I386)
    cur_regs.ebx = (long)tcp->childshm;
    cur_regs.edx = (long)(((char*)tcp->childshm) + len1 + 1);
#elif defined(X86_64)
    cur_regs.rdi = (long)tcp->childshm;
    cur_regs.rdx = (long)(((char*)tcp->childshm) + len1 + 1);
#else
  #error "Unknown architecture (not I386 or X86_64)"
#endif

    ptrace(PTRACE_SETREGS, tcp->pid, NULL, (long)&cur_regs);
  }
  else if (redirected_filename1) {
    strcpy(tcp->localshm, redirected_filename1);

    struct user_regs_struct cur_regs;
    EXITIF(ptrace(PTRACE_GETREGS, tcp->pid, NULL, (long)&cur_regs) < 0);

#if defined (I386)
    cur_regs.ebx = (long)tcp->childshm;
#elif defined(X86_64)
    cur_regs.rdi = (long)tcp->childshm;
#else
  #error "Unknown architecture (not I386 or X86_64)"
#endif

    ptrace(PTRACE_SETREGS, tcp->pid, NULL, (long)&cur_regs);
  }
  else if (redirected_filename2) {
    strcpy(tcp->localshm, redirected_filename2);

    struct user_regs_struct cur_regs;
    EXITIF(ptrace(PTRACE_GETREGS, tcp->pid, NULL, (long)&cur_regs) < 0);

#if defined (I386)
    cur_regs.edx = (long)tcp->childshm; // only set ECX
#elif defined(X86_64)
    cur_regs.rdx = (long)tcp->childshm;
#else
  #error "Unknown architecture (not I386 or X86_64)"
#endif

    ptrace(PTRACE_SETREGS, tcp->pid, NULL, (long)&cur_regs);
  }

  if (redirected_filename1) free(redirected_filename1);
  if (redirected_filename2) free(redirected_filename2);
}


// create a malloc'ed filename that contains a version within cde-root/
// return NULL if the filename should NOT be redirected
// WARNING: behavior differs based on CDE_exec_mode!
static char* redirect_filename_into_cderoot(char* filename, char* child_current_pwd) {
  /* sometimes this is called with a null arg ... investigate further
     before making this hack permanent, though
  if (!filename) {
    return NULL;
  }
  */
  assert(filename);
  assert(child_current_pwd);

  char* filename_abspath = NULL;
  if (CDE_exec_mode) {
    // canonicalize_path has the desirable side effect of preventing
    // 'malicious' paths from going below the pseudo-root '/' ... e.g.,
    // if filename is '/home/pgbovine/../../../../'
    // then filename_abspath is simply '/'
    //
    // we resolve relative paths w.r.t.
    // extract_sandboxed_pwd(child_current_pwd), so that programs
    // can't use relative paths like '../../../' to get out of sandbox
    //
    // this is why it's VERY IMPORTANT to canonicalize before creating a
    // path into CDE_ROOT_DIR, so that absolute paths can't 'escape'
    // the sandbox
    filename_abspath =
      canonicalize_path(filename, extract_sandboxed_pwd(child_current_pwd));
  }
  else {
    filename_abspath = canonicalize_path(filename, child_current_pwd);
  }
  assert(filename_abspath);


  // don't redirect paths that we're ignoring (remember to use ABSOLUTE PATH)
  if (ignore_path(filename_abspath)) {
    free(filename_abspath);
    return NULL;
  }


  // WARNING: behavior of create_abspath_within_cderoot
  // differs based on CDE_exec_mode!
  char* ret = create_abspath_within_cderoot(filename_abspath);
  free(filename_abspath);

  if (CDE_verbose_mode) {
    printf("redirect '%s' => '%s'\n", filename, ret);
  }

  return ret;
}


/* standard functionality for syscalls that take a filename as first argument

  trace mode:
    - ONLY on success, if abspath(filename) is outside pwd, then copy it
      into cde-root/
      - also, if filename is a symlink, then copy the target into the
        proper location (maybe using readlink?)

  exec mode:
    - if abspath(filename) is outside pwd, then redirect it into cde-root/

sys_open(filename, flags, mode)
sys_creat(filename, mode)
sys_chmod(filename, ...)
sys_chown(filename, ...)
sys_chown16(filename, ...)
sys_lchown(filename, ...)
sys_lchown16(filename, ...)
sys_stat(filename, ...)
sys_stat64(filename, ...)
sys_lstat(filename, ...)
sys_lstat64(filename, ...)
sys_truncate(path, length)
sys_truncate64(path, length)
sys_access(filename, mode)
sys_utime(filename, ...)
sys_readlink(path, ...)

 */
void CDE_begin_standard_fileop(struct tcb* tcp, const char* syscall_name) {
  assert(!tcp->opened_filename);
  tcp->opened_filename = strcpy_from_child(tcp, tcp->u_arg[0]);

  if (CDE_verbose_mode) {
    printf("BEGIN %s '%s'\n", syscall_name, tcp->opened_filename);
  }

  if (CDE_exec_mode) {
    modify_syscall_single_arg(tcp, 1);
  }
}

/* depending on value of success_type, do a different check for success

   success_type = 0 - zero return value is a success (e.g., for stat)
   success_type = 1 - non-negative return value is a success (e.g., for open or readlink)

 */
void CDE_end_standard_fileop(struct tcb* tcp, const char* syscall_name,
                             char success_type) {
  assert(tcp->opened_filename);

  if (CDE_verbose_mode) {
    printf("END   %s '%s' (%u)\n", syscall_name, tcp->opened_filename, tcp->u_rval);
  }
 

  if (CDE_exec_mode) {
    // empty
  }
  else {

    if (CDE_provenance_mode) {
      // only track open syscalls
      if ((success_type == 1) && (tcp->u_rval >= 0) &&
          strcmp(syscall_name, "sys_open") == 0) {
        // Note: tcp->u_arg[1] is only for open(), not openat()
        unsigned char open_mode = (tcp->u_arg[1] & 3);
        char is_read = 0;
        char is_write = 0;
        if (open_mode == O_RDONLY) {
          is_read = 1;
        }
        else if (open_mode == O_WRONLY) {
          is_write = 1;
        }
        else if (open_mode == O_RDWR) {
          is_read = 1;
          is_write = 1;
        }
        assert(is_read || is_write);

        char* filename_abspath = canonicalize_path(tcp->opened_filename, tcp->current_dir);
        assert(filename_abspath);
        if (is_read) {
          printf("PROVENANCE: %u READ %s\n", tcp->pid, filename_abspath);
        }
        if (is_write) {
          printf("PROVENANCE: %u WRITE %s\n", tcp->pid, filename_abspath);
        }
        free(filename_abspath);
      }
    }

    if (((success_type == 0) && (tcp->u_rval == 0)) ||
        ((success_type == 1) && (tcp->u_rval >= 0))) {
      copy_file_into_cde_root(tcp->opened_filename, tcp->current_dir);
    }
  }

  free(tcp->opened_filename);
  tcp->opened_filename = NULL;
}


/* standard functionality for *at syscalls that take a dirfd as first
   argument, followed by a filepath
   e.g., see documentation for http://linux.die.net/man/2/openat

  example syscalls:
    openat,faccessat,fstatat64,fchownat,fchmodat,futimesat,mknodat

  if filepath is an absolute path, or if filepath is a relative path but
  dirfd is AT_FDCWD, then:

  trace mode:
    - ONLY on success, if abspath(filepath) is outside pwd, then copy it
      into cde-root/

  exec mode:
    - if abspath(filepath) is outside pwd, then redirect it into cde-root/

  issue a warning if filepath is a relative path but dirfd is NOT AT_FDCWD
*/
void CDE_begin_at_fileop(struct tcb* tcp, const char* syscall_name) {
  assert(!tcp->opened_filename);
  tcp->opened_filename = strcpy_from_child(tcp, tcp->u_arg[1]);

  if (CDE_verbose_mode) {
    printf("BEGIN %s '%s' (dirfd=%d)\n", syscall_name, tcp->opened_filename, tcp->u_arg[0]);
  }

  if (!IS_ABSPATH(tcp->opened_filename) && tcp->u_arg[0] != AT_FDCWD) {
    fprintf(stderr,
            "CDE WARNING (unsupported operation): %s '%s' is a relative path and dirfd != AT_FDCWD\n",
            syscall_name, tcp->opened_filename);
    return; // punt early!
  }

  if (CDE_exec_mode) {
    modify_syscall_single_arg(tcp, 2);
  }
}

// we currently do the same thing as CDE_end_standard_fileop
void CDE_end_at_fileop(struct tcb* tcp, const char* syscall_name,
                       char success_type) {
  // punt early for this special case (see CDE_begin_at_fileop)
  if (!IS_ABSPATH(tcp->opened_filename) && tcp->u_arg[0] != AT_FDCWD) {
    free(tcp->opened_filename);
    tcp->opened_filename = NULL;
    return;
  }

  CDE_end_standard_fileop(tcp, syscall_name, success_type);
}


// output_buffer_arg_index is the index of the argument where the output
// buffer is being held (we clobber this in some special cases)
static void CDE_end_readlink_internal(struct tcb* tcp, int output_buffer_arg_index) {
  assert(tcp->opened_filename);
 
  if (CDE_exec_mode) {
    if (tcp->u_rval >= 0) {
      // super hack!  if the program is trying to access the special
      // /proc/self/exe file, return perceived_program_fullpath if
      // available, or else cde-exec will ERRONEOUSLY return the path
      // to the dynamic linker (e.g., ld-linux.so.2).
      //
      // programs like 'java' rely on the value of /proc/self/exe
      // being the true path to the executable, in order to dynamically
      // load libraries based on paths relative to that full path!
      char is_proc_self_exe = (strcmp(tcp->opened_filename, "/proc/self/exe") == 0);

      // another super hack!  programs like Google Earth
      // ('googleearth-bin') access /proc/self/exe as /proc/<pid>/exe
      // where <pid> is ITS OWN PID!  be sure to handle that case properly
      // (but don't worry about handling cases where <pid> is the PID of
      // another process).
      //
      // (again, these programs use the real path of /proc/<pid>/exe as
      // a basis for dynamically loading libraries, so we must properly
      // 'fake' this value)
      char* self_pid_name = format("/proc/%d/exe", tcp->pid);
      char is_proc_self_pid_exe = (strcmp(tcp->opened_filename, self_pid_name) == 0);
      free(self_pid_name);

      if ((is_proc_self_exe || is_proc_self_pid_exe) &&
          tcp->perceived_program_fullpath) {
        memcpy_to_child(tcp->pid, (char*)tcp->u_arg[output_buffer_arg_index],
                        tcp->perceived_program_fullpath,
                        strlen(tcp->perceived_program_fullpath) + 1);

        // VERY SUBTLE - set %eax (the syscall return value) to the length
        // of the FAKED STRING, since readlink is supposed to return the
        // length of the returned path (some programs like Python rely
        // on that length to allocated memory)
        struct user_regs_struct cur_regs;
        EXITIF(ptrace(PTRACE_GETREGS, tcp->pid, NULL, (long)&cur_regs) < 0);
#if defined (I386)
        cur_regs.eax = (long)strlen(tcp->perceived_program_fullpath);
#elif defined(X86_64)
        cur_regs.rax = (long)strlen(tcp->perceived_program_fullpath);
#else
    #error "Unknown architecture (not I386 or X86_64)"
#endif
        ptrace(PTRACE_SETREGS, tcp->pid, NULL, (long)&cur_regs);
      }
      // if the program tries to read /proc/self/cwd, then treat it like
      // a CDE_end_getcwd call, returning a fake cwd:
      //
      // (note that we don't handle /proc/<pid>/cwd yet)
      else if (strcmp(tcp->opened_filename, "/proc/self/cwd") == 0) {
        // copied from CDE_end_getcwd
        char* sandboxed_pwd = extract_sandboxed_pwd(tcp->current_dir);
        memcpy_to_child(tcp->pid, (char*)tcp->u_arg[output_buffer_arg_index],
                        sandboxed_pwd, strlen(sandboxed_pwd) + 1);

        // VERY SUBTLE - set %eax (the syscall return value) to the length
        // of the FAKED STRING, since readlink is supposed to return the
        // length of the returned path (some programs like Python rely
        // on that length to allocated memory)
        struct user_regs_struct cur_regs;
        EXITIF(ptrace(PTRACE_GETREGS, tcp->pid, NULL, (long)&cur_regs) < 0);
#if defined (I386)
        cur_regs.eax = (long)strlen(sandboxed_pwd);
#elif defined(X86_64)
        cur_regs.rax = (long)strlen(sandboxed_pwd);
#else
    #error "Unknown architecture (not I386 or X86_64)"
#endif
        ptrace(PTRACE_SETREGS, tcp->pid, NULL, (long)&cur_regs);
      }
    }
  }
  else {
    if (tcp->u_rval >= 0) {
      copy_file_into_cde_root(tcp->opened_filename, tcp->current_dir);
    }
  }

  free(tcp->opened_filename);
  tcp->opened_filename = NULL;
}

void CDE_end_readlink(struct tcb* tcp) {
  // output buffer is second argument (index 1)
  CDE_end_readlink_internal(tcp, 1);
}

void CDE_end_readlinkat(struct tcb* tcp) {
  // output buffer is third argument (index 2)
  CDE_end_readlink_internal(tcp, 2);
}


void CDE_begin_execve(struct tcb* tcp) {
  char* ld_linux_filename = NULL;
  char* ld_linux_fullpath = NULL;

  assert(!tcp->opened_filename);
  tcp->opened_filename = strcpy_from_child(tcp, tcp->u_arg[0]);

  // only attempt to do the ld-linux.so.2 trick if tcp->opened_filename
  // is a valid executable file ... otherwise don't do
  // anything and simply let the execve fail just like it's supposed to
  struct stat filename_stat;

  if (CDE_verbose_mode) {
    printf("CDE_begin_execve '%s'\n", tcp->opened_filename);
  }

  char* redirected_path = NULL;
  if (CDE_exec_mode) {
    // if we're purposely ignoring a path to an executable (e.g.,
    // ignoring "/bin/bash" to prevent crashes on certain Ubuntu
    // machines), then DO NOT use the ld-linux trick and simply
    // execve the file normally
    //
    // TODO: pass in an ABSOLUTE PATH to ignore_path for more
    //       robust behavior
    if (ignore_path(tcp->opened_filename)) {
      return;
    }

    redirected_path = redirect_filename_into_cderoot(tcp->opened_filename, tcp->current_dir);
  }

  char* path_to_executable = NULL;
  if (redirected_path) {
    // TODO: we don't check whether it's a real executable file :/
    if (stat(redirected_path, &filename_stat) != 0) {
      free(redirected_path);
      return;
    }
    path_to_executable = redirected_path;
  }
  else {
    // just check the file itself
    // TODO: we don't check whether it's a real executable file :/
    if (stat(tcp->opened_filename, &filename_stat) != 0) {
      return;
    }
    path_to_executable = tcp->opened_filename;
  }
  assert(path_to_executable);

  // WARNING: ld-linux.so.2 only works on dynamically-linked binary
  // executable files; it will fail if you invoke it on:
  //   - a textual script file
  //   - a statically-linked binary
  //
  // for a textual script file, we must invoke ld-linux.so.2 on the
  // target of the shebang #! (which can itself take arguments)
  //
  // e.g., #! /bin/sh
  // e.g., #! /usr/bin/env python
  char is_textual_script = 0;
  char is_elf_binary = 0;
  char* script_command = NULL;

  FILE* f = fopen(path_to_executable, "rb"); // open in binary mode
  assert(f);
  char header[5];
  memset(header, 0, sizeof(header));
  fgets(header, 5, f); // 5 means 4 bytes + 1 null terminating byte
  if (strcmp(header, "\177ELF") == 0) {
    is_elf_binary = 1;
  }
  fclose(f);

  if (is_elf_binary) {
    // look for whether it's a statically-linked binary ...
    // if so, then there is NO need to call ld-linux.so.2 on it;
    // we can just execute it directly (in fact, ld-linux.so.2
    // will fail on static binaries!)

    // mallocs a new string if successful
    // (this string is most likely "/lib/ld-linux.so.2")
    ld_linux_filename = find_ELF_program_interpreter(path_to_executable);
    if (!ld_linux_filename) {
      // if the program interpreter isn't found, then it's a static
      // binary, so let the execve call proceed normally
      if (CDE_exec_mode) {
        // redirect the executable's path to within $CDE_ROOT_DIR:
        modify_syscall_single_arg(tcp, 1);
      }

      // remember to EXIT EARLY!
      goto done;
    }
    assert(IS_ABSPATH(ld_linux_filename));
  }
  else {
    // find out whether it's a script file (starting with #! line)
    FILE* f = fopen(path_to_executable, "rb"); // open in binary mode

    size_t len = 0;
    ssize_t read;
    char* tmp = NULL; // getline() mallocs for us
    read = getline(&tmp, &len, f);
    if (read > 2) {
      assert(tmp[read-1] == '\n'); // strip of trailing newline
      tmp[read-1] = '\0'; // strip of trailing newline
      if (tmp[0] == '#' && tmp[1] == '!') {
        is_textual_script = 1;
        script_command = strdup(&tmp[2]);
      }
    }
    free(tmp);

    if (!script_command) {
      fprintf(stderr, "Fatal error: '%s' seems to be a script without a #! line.\n(cde can only execute scripts that start with a proper #! line)\n",
              path_to_executable);
      exit(1);
    }

    // now find the program interpreter for the script_command
    // executable, be sure to grab the FIRST TOKEN since that's
    // the actual executable name ...
    // TODO: this will fail if the executable's path has a space in it
    //
    // mallocs a new string if successful
    // (this string is most likely "/lib/ld-linux.so.2")

    // libc is so dumb ... strtok() alters its argument in an un-kosher way
    tmp = strdup(script_command);
    char* p = strtok(tmp, " ");

    // to have find_ELF_program_interpreter succeed, we might need to
    // redirect the path inside CDE_ROOT_DIR:
    char* script_command_filename = NULL;
    if (CDE_exec_mode) {
      script_command_filename = redirect_filename_into_cderoot(p, tcp->current_dir);
    }

    if (!script_command_filename) {
      script_command_filename = strdup(p);
    }

    ld_linux_filename = find_ELF_program_interpreter(script_command_filename);

    free(script_command_filename);
    free(tmp);

    if (!ld_linux_filename) {
      // if the program interpreter isn't found, then it's a static
      // binary, so let the execve call proceed unmodified

      // TODO: is this the right thing to do here?  I think we might
      // need to do something better here (think harder about this case!)
      if (CDE_exec_mode) {
        // redirect the executable's path to within $CDE_ROOT_DIR:
        modify_syscall_single_arg(tcp, 1);
      }

      goto done;
    }
    assert(IS_ABSPATH(ld_linux_filename));
  }

  assert(!(is_elf_binary && is_textual_script));

  if (CDE_exec_mode) {
    // set up shared memory segment if we haven't done so yet
    if (!tcp->childshm) {
      begin_setup_shmat(tcp);

      // no more need for filename, so don't leak it
      free(tcp->opened_filename);
      tcp->opened_filename = NULL;

      goto done; // MUST punt early here!!!
    }

    ld_linux_fullpath = create_abspath_within_cderoot(ld_linux_filename);

    /* we're gonna do some craziness here to redirect the OS to call
       cde-root/lib/ld-linux.so.2 rather than the real program, since
       ld-linux.so.2 is closely-tied with the version of libc in
       cde-root/. */
    if (is_textual_script) {
      /*  we're running a script with a shebang (#!), so
          let's set up the shared memory segment (tcp->localshm) like so:

    base -->       tcp->localshm : "cde-root/lib/ld-linux.so.2" (ld_linux_fullpath)
          script_command token 0 : "/usr/bin/env"
          script_command token 1 : "python"
              ... (for as many tokens as available) ...
    new_argv -->   argv pointers : point to tcp->childshm ("cde-root/lib/ld-linux.so.2")
                   argv pointers : point to script_command token 0
                   argv pointers : point to script_command token 1
              ... (for as many tokens as available) ...
                   argv pointers : point to tcp->u_arg[0] (original program name)
                   argv pointers : point to child program's argv[1]
                   argv pointers : point to child program's argv[2]
                   argv pointers : point to child program's argv[3]
                   argv pointers : [...]
                   argv pointers : NULL

        Note that we only need to do this if we're in CDE_exec_mode */

      //printf("script_command='%s', path_to_executable='%s'\n", script_command, path_to_executable);

      char* base = (char*)tcp->localshm;
      strcpy(base, ld_linux_fullpath);
      int ld_linux_offset = strlen(ld_linux_fullpath) + 1;

      char* cur_loc = (char*)(base + ld_linux_offset);
      char* script_command_token_starts[30]; // stores starting locations of each token

      int script_command_num_tokens = 0;

      // set this ONCE on the first token
      tcp->perceived_program_fullpath = NULL;

      // tokenize script_command into tokens, and insert them into argv
      // TODO: this will fail if the shebang line contains file paths
      // with spaces, quotes, or other weird characters!
      char* p;
      for (p = strtok(script_command, " "); p; p = strtok(NULL, " ")) {
        //printf("  token = %s\n", p);

        // set to the first token!
        if (!tcp->perceived_program_fullpath) {
          tcp->perceived_program_fullpath = strdup(p);
        }

        strcpy(cur_loc, p);
        script_command_token_starts[script_command_num_tokens] = cur_loc;

        cur_loc += (strlen(p) + 1);
        script_command_num_tokens++;
      }

      char** new_argv = (char**)(cur_loc);

      // really subtle, these addresses should be in the CHILD's address space,
      // not the parent's

      // points to ld_linux_fullpath
      new_argv[0] = (char*)tcp->childshm;

      // points to all the tokens of script_command
      int i;
      for (i = 0; i < script_command_num_tokens; i++) {
        new_argv[i+1] = (char*)tcp->childshm + (script_command_token_starts[i] - base);
      }

      // now populate the original program name from tcp->u_arg[0]
      new_argv[script_command_num_tokens + 1] = (char*)tcp->u_arg[0];

      // now populate argv[script_command_num_tokens+1:] directly from child's original space
      // (original arguments)
      char** child_argv = (char**)tcp->u_arg[1]; // in child's address space
      char* cur_arg = NULL;
      i = 1; // start at argv[1]
      while (1) {
        EXITIF(umovestr(tcp, (long)(child_argv + i), sizeof cur_arg, (void*)&cur_arg) < 0);
        new_argv[i + script_command_num_tokens + 1] = cur_arg;
        if (cur_arg == NULL) {
          break;
        }
        i++;
      }

      /*
      i = 0;
      cur_arg = NULL;
      while (1) {
        cur_arg = new_argv[i];
        if (cur_arg) {
          printf("new_argv[%d] = %s\n", i, strcpy_from_child(tcp, cur_arg));
          i++;
        }
        // argv is null-terminated
        else {
          break;
        }
      }
      */

      // now set ebx to the new program name and ecx to the new argv array
      // to alter the arguments of the execv system call :0
      struct user_regs_struct cur_regs;
      EXITIF(ptrace(PTRACE_GETREGS, tcp->pid, NULL, (long)&cur_regs) < 0);

#if defined (I386)
      cur_regs.ebx = (long)tcp->childshm;            // location of base
      cur_regs.ecx = ((long)tcp->childshm) + ((char*)new_argv - base); // location of new_argv
#elif defined(X86_64)
      cur_regs.rdi = (long)tcp->childshm;
      cur_regs.rsi = ((long)tcp->childshm) + ((char*)new_argv - base);
#else
  #error "Unknown architecture (not I386 or X86_64)"
#endif

      ptrace(PTRACE_SETREGS, tcp->pid, NULL, (long)&cur_regs);
    }
    else {
      /* we're running a dynamically-linked binary executable, go
         let's set up the shared memory segment (tcp->localshm) like so:

    base -->       tcp->localshm : "cde-root/lib/ld-linux.so.2" (ld_linux_fullpath)
    new_argv -->   argv pointers : point to tcp->childshm ("cde-root/lib/ld-linux.so.2")
                   argv pointers : point to tcp->u_arg[0] (original program name)
                   argv pointers : point to child program's argv[1]
                   argv pointers : point to child program's argv[2]
                   argv pointers : point to child program's argv[3]
                   argv pointers : [...]
                   argv pointers : NULL

        Note that we only need to do this if we're in CDE_exec_mode */

      char* base = (char*)tcp->localshm;
      strcpy(base, ld_linux_fullpath);
      int offset = strlen(ld_linux_fullpath) + 1;
      char** new_argv = (char**)(base + offset);

      // really subtle, these addresses should be in the CHILD's address space,
      // not the parent's

      // points to ld_linux_fullpath
      new_argv[0] = (char*)tcp->childshm;
      // points to original program name (full path)
      new_argv[1] = (char*)tcp->u_arg[0];

      tcp->perceived_program_fullpath = strcpy_from_child(tcp, tcp->u_arg[0]);

      // now populate argv[1:] directly from child's original space
      // (original arguments)
   
      char** child_argv = (char**)tcp->u_arg[1]; // in child's address space
      char* cur_arg = NULL;
      int i = 1; // start at argv[1], since we're ignoring argv[0]
      while (1) {
        EXITIF(umovestr(tcp, (long)(child_argv + i), sizeof cur_arg, (void*)&cur_arg) < 0);
        new_argv[i + 1] = cur_arg;
        if (cur_arg == NULL) {
          break;
        }
        i++;
      }

      /*
      i = 0;
      cur_arg = NULL;
      while (1) {
        cur_arg = new_argv[i];
        if (cur_arg) {
          printf("new_argv[%d] = %s\n", i, strcpy_from_child(tcp, cur_arg));
          i++;
        }
        // argv is null-terminated
        else {
          break;
        }
      }
      */

      // now set ebx to the new program name and ecx to the new argv array
      // to alter the arguments of the execv system call :0
      struct user_regs_struct cur_regs;
      EXITIF(ptrace(PTRACE_GETREGS, tcp->pid, NULL, (long)&cur_regs) < 0);

#if defined (I386)
      cur_regs.ebx = (long)tcp->childshm;            // location of base
      cur_regs.ecx = ((long)tcp->childshm) + offset; // location of new_argv
#elif defined(X86_64)
      cur_regs.rdi = (long)tcp->childshm;
      cur_regs.rsi = ((long)tcp->childshm) + offset;
#else
  #error "Unknown architecture (not I386 or X86_64)"
#endif

      ptrace(PTRACE_SETREGS, tcp->pid, NULL, (long)&cur_regs);
    }

    // if tcp->perceived_program_fullpath has been set, then it might be
    // a RELATIVE PATH (e.g., ./googleearth-bin), so we need to make it
    // into an ABSOLUTE PATH within cde-root/, but to only grab the
    // component that comes after cde-root/, since that's what the
    // program PERCEIVES its full path to be
    if (tcp->perceived_program_fullpath) {
      char* redirected_path =
        redirect_filename_into_cderoot(tcp->perceived_program_fullpath,
                                       tcp->current_dir);
      // redirected_path could be NULL (e.g., if it's in cde.ignore),
      // in which case just do nothing
      if (redirected_path) {
        char* old_perceived_program_fullpath = tcp->perceived_program_fullpath;

        // extract_sandboxed_pwd (perhaps badly named for this scenario)
        // extracts the part of redirected_path that comes AFTER cde-root/
        // (note that extract_sandboxed_pwd does NOT malloc a new string)
        tcp->perceived_program_fullpath =
          strdup(extract_sandboxed_pwd(redirected_path));

        free(old_perceived_program_fullpath);
      }
    }

  }
  else {
    if (ld_linux_filename) {
      // copy ld-linux.so.2 (or whatever the program interpreter is) into cde-root
      copy_file_into_cde_root(ld_linux_filename, tcp->current_dir);
    }

    // very subtle!  if we're executing a textual script with a #!, we
    // need to grab the name of the executable from the #! string into
    // cde-root, since strace doesn't normally pick it up as a dependency
    if (is_textual_script) {
      //printf("script_command='%s', path_to_executable='%s'\n", script_command, path_to_executable);
      char* p;
      for (p = strtok(script_command, " "); p; p = strtok(NULL, " ")) {
        struct stat p_stat;
        if (stat(p, &p_stat) == 0) {
          copy_file_into_cde_root(p, tcp->current_dir);
        }
        break;
      }
    }
  }

done:
  if (redirected_path) {
    free(redirected_path);
  }

  if (script_command) {
    free(script_command);
  }

  if (ld_linux_filename) {
    free(ld_linux_filename);
  }

  if (ld_linux_fullpath) {
    free(ld_linux_fullpath);
  }
}


void CDE_end_execve(struct tcb* tcp) {
  assert(tcp->opened_filename);

  if (CDE_exec_mode) {
    // WOW, what a gross hack!  execve detaches all shared memory
    // segments, so childshm is no longer valid.  we must clear it so
    // that begin_setup_shmat() will be called again
    tcp->childshm = NULL;
  }
  else {
    // return value of 0 means a successful call
    if (tcp->u_rval == 0) {
      copy_file_into_cde_root(tcp->opened_filename, tcp->current_dir);
    }
  }

  free(tcp->opened_filename);
  tcp->opened_filename = NULL;
}


void CDE_begin_file_unlink(struct tcb* tcp) {
  assert(!tcp->opened_filename);
  tcp->opened_filename = strcpy_from_child(tcp, tcp->u_arg[0]);
  //printf("CDE_begin_file_unlink %s\n", tcp->opened_filename);

  if (CDE_exec_mode) {
    modify_syscall_single_arg(tcp, 1);
  }
  else {
    char* redirected_path =
      redirect_filename_into_cderoot(tcp->opened_filename, tcp->current_dir);
    if (redirected_path) {
      unlink(redirected_path);
      free(redirected_path);
    }
  }

  // no need for this anymore
  free(tcp->opened_filename);
  tcp->opened_filename = NULL;
}

// copy-and-paste from CDE_begin_file_unlink,
// except adjusting for unlinkat signature:
//   int unlinkat(int dirfd, const char *pathname, int flags);
void CDE_begin_file_unlinkat(struct tcb* tcp) {
  assert(!tcp->opened_filename);
  tcp->opened_filename = strcpy_from_child(tcp, tcp->u_arg[1]);

  if (!IS_ABSPATH(tcp->opened_filename) && tcp->u_arg[0] != AT_FDCWD) {
    fprintf(stderr,
            "CDE WARNING: unlinkat '%s' is a relative path and dirfd != AT_FDCWD\n",
            tcp->opened_filename);
    goto done; // punt early!
  }

  if (CDE_exec_mode) {
    modify_syscall_single_arg(tcp, 2);
  }
  else {
    char* redirected_path =
      redirect_filename_into_cderoot(tcp->opened_filename, tcp->current_dir);
    if (redirected_path) {
      unlink(redirected_path);
      free(redirected_path);
    }
  }


done:
  // no need for this anymore
  free(tcp->opened_filename);
  tcp->opened_filename = NULL;
}


void CDE_begin_file_link(struct tcb* tcp) {
  //printf("CDE_begin_file_link\n");
  if (CDE_exec_mode) {
    modify_syscall_two_args(tcp);
  }
}

void CDE_end_file_link(struct tcb* tcp) {
  if (CDE_exec_mode) {
    // empty
  }
  else {
    if (tcp->u_rval == 0) {
      char* filename1 = strcpy_from_child(tcp, tcp->u_arg[0]);
      char* redirected_filename1 =
        redirect_filename_into_cderoot(filename1, tcp->current_dir);
      // first copy the origin file into cde-root/ before trying to link it
      copy_file_into_cde_root(filename1, tcp->current_dir);

      char* filename2 = strcpy_from_child(tcp, tcp->u_arg[1]);
      char* redirected_filename2 =
        redirect_filename_into_cderoot(filename2, tcp->current_dir);

      link(redirected_filename1, redirected_filename2);

      free(filename1);
      free(filename2);
      free(redirected_filename1);
      free(redirected_filename2);
    }
  }
}

// copy-and-paste from file_link functions above,
// except adjusting for linkat signature:
//   linkat(int olddirfd, char* oldpath, int newdirfd, char* newpath, int flags);
void CDE_begin_file_linkat(struct tcb* tcp) {
  char* oldpath = strcpy_from_child(tcp, tcp->u_arg[1]);
  char* newpath = strcpy_from_child(tcp, tcp->u_arg[3]);

  if (!IS_ABSPATH(oldpath) && tcp->u_arg[0] != AT_FDCWD) {
    fprintf(stderr,
            "CDE WARNING: linkat '%s' is a relative path and dirfd != AT_FDCWD\n",
            oldpath);
    goto done; // punt early!
  }
  if (!IS_ABSPATH(newpath) && tcp->u_arg[2] != AT_FDCWD) {
    fprintf(stderr,
            "CDE WARNING: linkat '%s' is a relative path and dirfd != AT_FDCWD\n",
            newpath);
    goto done; // punt early!
  }

  if (CDE_exec_mode) {
    modify_syscall_second_and_fourth_args(tcp);
  }

done:
  free(oldpath);
  free(newpath);
}

void CDE_end_file_linkat(struct tcb* tcp) {
  if (CDE_exec_mode) {
    // empty
  }
  else {
    if (tcp->u_rval == 0) {
      char* filename1 = strcpy_from_child(tcp, tcp->u_arg[1]);
      char* redirected_filename1 =
        redirect_filename_into_cderoot(filename1, tcp->current_dir);
      // first copy the origin file into cde-root/ before trying to link it
      copy_file_into_cde_root(filename1, tcp->current_dir);

      char* filename2 = strcpy_from_child(tcp, tcp->u_arg[3]);
      char* redirected_filename2 =
        redirect_filename_into_cderoot(filename2, tcp->current_dir);

      link(redirected_filename1, redirected_filename2);

      free(filename1);
      free(filename2);
      free(redirected_filename1);
      free(redirected_filename2);
    }
  }
}


void CDE_begin_file_symlink(struct tcb* tcp) {
  //printf("CDE_begin_file_symlink\n");
  if (CDE_exec_mode) {
    modify_syscall_two_args(tcp);
  }
}

void CDE_end_file_symlink(struct tcb* tcp) {
  if (CDE_exec_mode) {
    // empty
  }
  else {
    if (tcp->u_rval == 0) {
      char* oldname = strcpy_from_child(tcp, tcp->u_arg[0]);
      char* newname = strcpy_from_child(tcp, tcp->u_arg[1]);
      char* newname_redirected =
        redirect_filename_into_cderoot(newname, tcp->current_dir);

      symlink(oldname, newname_redirected);

      free(oldname);
      free(newname);
      free(newname_redirected);
    }
  }
}


// copy-and-paste from above,
// except adjusting for symlinkat signature:
//   symlinkat(char* oldpath, int newdirfd, char* newpath);
void CDE_begin_file_symlinkat(struct tcb* tcp) {
  char* newpath = strcpy_from_child(tcp, tcp->u_arg[2]);

  if (!IS_ABSPATH(newpath) && tcp->u_arg[1] != AT_FDCWD) {
    fprintf(stderr,
            "CDE WARNING: symlinkat '%s' is a relative path and dirfd != AT_FDCWD\n",
            newpath);
    free(newpath);
    return; // punt early!
  }
  
  if (CDE_exec_mode) {
    modify_syscall_first_and_third_args(tcp);
  }

  free(newpath);
}

void CDE_end_file_symlinkat(struct tcb* tcp) {
  if (CDE_exec_mode) {
    // empty
  }
  else {
    if (tcp->u_rval == 0) {
      char* oldname = strcpy_from_child(tcp, tcp->u_arg[0]);
      char* newname = strcpy_from_child(tcp, tcp->u_arg[2]);
      char* newname_redirected =
        redirect_filename_into_cderoot(newname, tcp->current_dir);

      symlink(oldname, newname_redirected);

      free(oldname);
      free(newname);
      free(newname_redirected);
    }
  }
}


void CDE_begin_file_rename(struct tcb* tcp) {
  if (CDE_exec_mode) {
    modify_syscall_two_args(tcp);
  }
}

void CDE_end_file_rename(struct tcb* tcp) {
  if (CDE_exec_mode) {
    // empty
  }
  else {
    if (tcp->u_rval == 0) {
      char* filename1 = strcpy_from_child(tcp, tcp->u_arg[0]);
      char* redirected_filename1 =
        redirect_filename_into_cderoot(filename1, tcp->current_dir);
      free(filename1);
      // remove original file from cde-root/
      if (redirected_filename1) {
        unlink(redirected_filename1);
        free(redirected_filename1);
      }

      // copy the destination file into cde-root/
      char* dst_filename = strcpy_from_child(tcp, tcp->u_arg[1]);
      copy_file_into_cde_root(dst_filename, tcp->current_dir);
      free(dst_filename);
    }
  }
}


// copy-and-paste from file_rename functions above,
// except adjusting for linkat signature:
//   renameat(int olddirfd, char* oldpath, int newdirfd, char* newpath);
void CDE_begin_file_renameat(struct tcb* tcp) {
  char* oldpath = strcpy_from_child(tcp, tcp->u_arg[1]);
  char* newpath = strcpy_from_child(tcp, tcp->u_arg[3]);

  if (!IS_ABSPATH(oldpath) && tcp->u_arg[0] != AT_FDCWD) {
    fprintf(stderr,
            "CDE WARNING: renameat '%s' is a relative path and dirfd != AT_FDCWD\n",
            oldpath);
    goto done; // punt early!
  }
  if (!IS_ABSPATH(newpath) && tcp->u_arg[2] != AT_FDCWD) {
    fprintf(stderr,
            "CDE WARNING: renameat '%s' is a relative path and dirfd != AT_FDCWD\n",
            newpath);
    goto done; // punt early!
  }

  if (CDE_exec_mode) {
    modify_syscall_second_and_fourth_args(tcp);
  }

done:
  free(oldpath);
  free(newpath);
}

void CDE_end_file_renameat(struct tcb* tcp) {
  if (CDE_exec_mode) {
    // empty
  }
  else {
    if (tcp->u_rval == 0) {
      char* filename1 = strcpy_from_child(tcp, tcp->u_arg[1]);
      char* redirected_filename1 =
        redirect_filename_into_cderoot(filename1, tcp->current_dir);
      free(filename1);
      // remove original file from cde-root/
      if (redirected_filename1) {
        unlink(redirected_filename1);
        free(redirected_filename1);
      }

      // copy the destination file into cde-root/
      char* dst_filename = strcpy_from_child(tcp, tcp->u_arg[3]);
      copy_file_into_cde_root(dst_filename, tcp->current_dir);
      free(dst_filename);
    }
  }
}


void CDE_begin_chdir(struct tcb* tcp) {
  CDE_begin_standard_fileop(tcp, "chdir");
}

void CDE_end_fchdir(struct tcb* tcp);

// don't forget that tcp->opened_filename has been initialized here
void CDE_end_chdir(struct tcb* tcp) {
  assert(tcp->opened_filename);

  CDE_end_fchdir(tcp); // this will update tcp->current_dir

  free(tcp->opened_filename);
  tcp->opened_filename = NULL;
}

void CDE_end_fchdir(struct tcb* tcp) {
  // only do this on success
  if (tcp->u_rval == 0) {
    // update current_dir

    // A reliable way to get the current directory is using /proc/<pid>/cwd
    char* cwd_symlink_name = format("/proc/%d/cwd", tcp->pid);

    tcp->current_dir[0] = '\0';
    int len = readlink(cwd_symlink_name, tcp->current_dir, MAXPATHLEN);
    assert(tcp->current_dir[0] != '\0');
    assert(len >= 0);
    tcp->current_dir[len] = '\0'; // wow, readlink doesn't put the cap on the end!!!

    free(cwd_symlink_name);


    // now copy into cde-root/ if necessary
    if (!CDE_exec_mode) {
      char* redirected_path =
        redirect_filename_into_cderoot(tcp->current_dir, tcp->current_dir);
      if (redirected_path) {
        //mkdir_recursive(redirected_path, 0);
        make_mirror_dirs_in_cde_package(tcp->current_dir, 0);
        free(redirected_path);
      }
    }
  }
}


void CDE_begin_mkdir(struct tcb* tcp) {
  CDE_begin_standard_fileop(tcp, "mkdir");
}

void CDE_end_mkdir(struct tcb* tcp) {
  assert(tcp->opened_filename);

  if (CDE_exec_mode) {
    // empty
  }
  else {
    // always mkdir even if the call fails
    // (e.g., because the directory already exists)
    char* dirname_abspath = canonicalize_path(tcp->opened_filename, tcp->current_dir);
    make_mirror_dirs_in_cde_package(dirname_abspath, 0);
    free(dirname_abspath);
  }

  free(tcp->opened_filename);
  tcp->opened_filename = NULL;
}

// copy-and-paste from mkdir functions above,
// except adjusting for mkdirat signature:
//   int mkdirat(int dirfd, const char *pathname, mode_t mode);
void CDE_begin_mkdirat(struct tcb* tcp) {
  CDE_begin_at_fileop(tcp, "mkdirat");
}

void CDE_end_mkdirat(struct tcb* tcp) {
  CDE_end_mkdir(tcp);
}


void CDE_begin_rmdir(struct tcb* tcp) {
  CDE_begin_standard_fileop(tcp, "rmdir");
}

void CDE_end_rmdir(struct tcb* tcp) {
  assert(tcp->opened_filename);

  if (CDE_exec_mode) {
    // empty
  }
  else {
    if (tcp->u_rval == 0) {
      char* redirected_path =
        redirect_filename_into_cderoot(tcp->opened_filename, tcp->current_dir);
      if (redirected_path) {
        rmdir(redirected_path);
        free(redirected_path);
      }
    }
  }

  free(tcp->opened_filename);
  tcp->opened_filename = NULL;
}


void CDE_begin_unlinkat_rmdir(struct tcb* tcp) {
  CDE_begin_at_fileop(tcp, "unlinkat_rmdir");
}

void CDE_end_unlinkat_rmdir(struct tcb* tcp) {
  CDE_end_rmdir(tcp);
}


// from Goanna
#define FILEBACK 8 /* It is OK to use a file backed region. */

// TODO: this is probably very Linux-specific ;)
static void* find_free_addr(int pid, int prot, unsigned long size) {
  FILE *f;
  char filename[20];
  char s[80];
  char r, w, x, p;

  sprintf(filename, "/proc/%d/maps", pid);

  f = fopen(filename, "r");
  if (!f) {
    fprintf(stderr, "Can not find a free address in pid %d: %s\n.", pid, strerror(errno));
  }
  while (fgets(s, sizeof(s), f) != NULL) {
    unsigned long cstart, cend;
    int major, minor;

    sscanf(s, "%lx-%lx %c%c%c%c %*x %d:%d", &cstart, &cend, &r, &w, &x, &p, &major, &minor);

    if (cend - cstart < size) {
      continue;
    }

    if (!(prot & FILEBACK) && (major || minor)) {
      continue;
    }

    if (p != 'p') {
      continue;
    }
    if ((prot & PROT_READ) && (r != 'r')) {
      continue;
    }
    if ((prot & PROT_EXEC) && (x != 'x')) {
      continue;
    }
    if ((prot & PROT_WRITE) && (w != 'w')) {
      continue;
    }
    fclose(f);

    return (void *)cstart;
  }
  fclose(f);

  return NULL;
}


void alloc_tcb_CDE_fields(struct tcb* tcp) {
  tcp->localshm = NULL;
  tcp->childshm = NULL;
  tcp->setting_up_shm = 0;

  if (CDE_exec_mode) {
    key_t key;
    // randomly probe for a valid shm key
    do {
      errno = 0;
      key = rand();
      tcp->shmid = shmget(key, SHARED_PAGE_SIZE, IPC_CREAT|IPC_EXCL|0600);
    } while (tcp->shmid == -1 && errno == EEXIST);

    tcp->localshm = (char*)shmat(tcp->shmid, NULL, 0);

    if ((long)tcp->localshm == -1) {
      perror("shmat");
      exit(1);
    }

    if (shmctl(tcp->shmid, IPC_RMID, NULL) == -1) {
      perror("shmctl(IPC_RMID)");
      exit(1);
    }

    assert(tcp->localshm);
  }

  tcp->current_dir = NULL;
}

void free_tcb_CDE_fields(struct tcb* tcp) {
  if (tcp->localshm) {
    shmdt(tcp->localshm);
  }
  // need to null out elts in case table entries are recycled
  tcp->localshm = NULL;
  tcp->childshm = NULL;
  tcp->setting_up_shm = 0;

  if (tcp->current_dir) {
    free(tcp->current_dir);
    tcp->current_dir = NULL;
  }
}


// inject a system call in the child process to tell it to attach our
// shared memory segment, so that it can read modified paths from there
//
// Setup a shared memory region within child process,
// then repeat current system call
static void begin_setup_shmat(struct tcb* tcp) {
  assert(tcp->localshm);
  assert(!tcp->childshm); // avoid duplicate calls

  // stash away original registers so that we can restore them later
  struct user_regs_struct cur_regs;
  EXITIF(ptrace(PTRACE_GETREGS, tcp->pid, NULL, (long)&cur_regs) < 0);
  memcpy(&tcp->saved_regs, &cur_regs, sizeof(cur_regs));

#if defined (I386)
  // The return value of shmat (attached address) is actually stored in
  // the child's address space
  tcp->savedaddr = find_free_addr(tcp->pid, PROT_READ|PROT_WRITE, sizeof(int));
  tcp->savedword = ptrace(PTRACE_PEEKDATA, tcp->pid, tcp->savedaddr, 0);
  EXITIF(errno); // PTRACE_PEEKDATA reports error in errno

  /* The shmat call is implemented as a godawful sys_ipc. */
  cur_regs.orig_eax = __NR_ipc;
  /* The parameters are passed in ebx, ecx, edx, esi, edi, and ebp */
  cur_regs.ebx = SHMAT;
  /* The kernel names the rest of these, first, second, third, ptr,
   * and fifth. Only first, second and ptr are used as inputs.  Third
   * is a pointer to the output (unsigned long).
   */
  cur_regs.ecx = tcp->shmid;
  cur_regs.edx = 0; /* shmat flags */
  cur_regs.esi = (long)tcp->savedaddr; /* Pointer to the return value in the
                                          child's address space. */
  cur_regs.edi = (long)NULL; /* We don't use shmat's shmaddr */
  cur_regs.ebp = 0; /* The "fifth" argument is unused. */
#elif defined(X86_64)
  // there is a direct shmat syscall in x86-64!!!
  cur_regs.orig_rax = __NR_shmat;
  cur_regs.rdi = tcp->shmid;
  cur_regs.rsi = 0;
  cur_regs.rdx = 0;
#else
  #error "Unknown architecture (not I386 or X86_64)"
#endif

  EXITIF(ptrace(PTRACE_SETREGS, tcp->pid, NULL, (long)&cur_regs) < 0);

  tcp->setting_up_shm = 1; // very importante!!!
}

void finish_setup_shmat(struct tcb* tcp) {
  struct user_regs_struct cur_regs;
  EXITIF(ptrace(PTRACE_GETREGS, tcp->pid, NULL, (long)&cur_regs) < 0);

#if defined (I386)
  // setup had better been a success!
  assert(cur_regs.orig_eax == __NR_ipc);
  assert(cur_regs.eax == 0);

  errno = 0;
  tcp->childshm = (void*)ptrace(PTRACE_PEEKDATA, tcp->pid, tcp->savedaddr, 0);
  EXITIF(errno); // PTRACE_PEEKDATA reports error in errno

  // restore original data in child's address space
  EXITIF(ptrace(PTRACE_POKEDATA, tcp->pid, tcp->savedaddr, tcp->savedword));

  tcp->saved_regs.eax = tcp->saved_regs.orig_eax;

  // back up IP so that we can re-execute previous instruction
  // TODO: is the use of 2 specific to 32-bit machines?
  tcp->saved_regs.eip = tcp->saved_regs.eip - 2;
#elif defined(X86_64)
  // there seems to be a direct shmat syscall in x86-64
  assert(cur_regs.orig_rax == __NR_shmat);

  // the return value of the direct shmat syscall is in %rax
  tcp->childshm = (void*)cur_regs.rax;

  tcp->saved_regs.rax = tcp->saved_regs.orig_rax;

  // back up IP so that we can re-execute previous instruction
  // TODO: wow, apparently the -2 offset works for 64-bit as well :)
  tcp->saved_regs.rip = tcp->saved_regs.rip - 2;
#else
  #error "Unknown architecture (not I386 or X86_64)"
#endif

  EXITIF(ptrace(PTRACE_SETREGS, tcp->pid, NULL, (long)&tcp->saved_regs) < 0);

  assert(tcp->childshm);

  tcp->setting_up_shm = 0; // very importante!!!
}


// copy src into dst, redirecting it into cde-root/ if necessary
// based on cde_starting_pwd
//
// dst should be big enough to hold a full path
void strcpy_redirected_cderoot(char* dst, char* src) {
  assert(CDE_exec_mode);
  // use cde_starting_pwd (TODO: is that correct?)
  char* redirected_src = redirect_filename_into_cderoot(src, cde_starting_pwd);
  if (redirected_src) {
    strcpy(dst, redirected_src);
    free(redirected_src);
  }
  else {
    strcpy(dst, src);
  }
}

// malloc a new string from child
static char* strcpy_from_child(struct tcb* tcp, long addr) {
  char path[MAXPATHLEN];
  EXITIF(umovestr(tcp, addr, sizeof path, path) < 0);
  return strdup(path);
}

// adapted from the Goanna project by Spillane et al.
// dst_in_child is a pointer in the child's address space
static void memcpy_to_child(int pid, char* dst_child, char* src, int size) {
  while (size >= sizeof(int)) {
    long w = *((long*)src);
    EXITIF(ptrace(PTRACE_POKEDATA, pid, dst_child, (long)w) < 0);
    size -= sizeof(int);
    dst_child = (char*)dst_child + sizeof(int);
    src = (char*)src + sizeof(int);
  }

  /* Cleanup the last little bit. */
  if (size) {
    union {
        long l;
        char c[4];
    } dw, sw;
    errno = 0;
    dw.l = ptrace(PTRACE_PEEKDATA, pid, dst_child, 0);
    EXITIF(errno);
    sw.l = *((long*)src);

    /* Little endian sucks. */
    dw.c[0] = sw.c[0];
    if (size >= 2)
      dw.c[1] = sw.c[1];
    if (size >= 3)
      dw.c[2] = sw.c[2];
	  assert(size < 4);

    EXITIF(ptrace(PTRACE_POKEDATA, pid, dst_child, dw.l) < 0);
  }
}


// TODO: do we still need to keep track of tcp->child_current_pwd
// if we can just directly access it using /proc/<pid>/cwd ???
void CDE_end_getcwd(struct tcb* tcp) {
  if (!syserror(tcp)) {
    if (CDE_exec_mode) {
      char* sandboxed_pwd = extract_sandboxed_pwd(tcp->current_dir);
      memcpy_to_child(tcp->pid, (char*)tcp->u_arg[0],
                      sandboxed_pwd, strlen(sandboxed_pwd) + 1);

      // for debugging
      //char* tmp = strcpy_from_child(tcp, tcp->u_arg[0]);
      //printf("[%d] CDE_end_getcwd spoofed: %s\n", tcp->pid, tmp);
      //free(tmp);
    }
    else {
      char* tmp = strcpy_from_child(tcp, tcp->u_arg[0]);
      strcpy(tcp->current_dir, tmp);
      free(tmp);
      //printf("[%d] CDE_end_getcwd: %s\n", tcp->pid, tcp->current_dir);
    }
  }
}


// path_envvar is $PATH.  Iterate through all entries and if any of them
// are symlinks, then create their corresponding entries in cde-root/.
// This takes care of cases where, say, /bin is actually a symlink to
// another directory like /KNOPPIX/bin.  We need to create a symlink
// 'bin' in cde-root/ and point it to ./KNOPPIX/bin
//
// DO THIS AT THE VERY BEGINNING OF EXECUTION!
void CDE_create_path_symlink_dirs() {
  char *p;
  int m, n;
  struct stat st;
  char tmp_buf[MAXPATHLEN];

  for (p = getenv("PATH"); p && *p; p += m) {
    if (strchr(p, ':')) {
      n = strchr(p, ':') - p;
      m = n + 1;
    }
    else {
      m = n = strlen(p);
    }

    strncpy(tmp_buf, p, n);
    tmp_buf[n] = '\0';

    // this will NOT follow the symlink ...
    if (lstat(tmp_buf, &st) == 0) {
      char is_symlink = S_ISLNK(st.st_mode);
      if (is_symlink) {
        char* tmp = strdup(tmp_buf);
        copy_file_into_cde_root(tmp, cde_starting_pwd);
        free(tmp);
      }
    }
  }

  // also, this is hacky, but also check /usr/lib to see
  // whether it's a symlink.  ld-linux.so.2 will likely try to look
  // for libraries in those places, but they're not in any convenient
  // environment variable
  //
  // note that the other 2 directories that ld-linux.so.2 usually
  // tries to look for libs in, /bin and /lib, will be taken care of by
  // CDE_create_toplevel_symlink_dirs()
  strcpy(tmp_buf, "/usr/lib");
  // this will NOT follow the symlink ...
  if (lstat(tmp_buf, &st) == 0) {
    char is_symlink = S_ISLNK(st.st_mode);
    if (is_symlink) {
      char* tmp = strdup(tmp_buf);
      copy_file_into_cde_root(tmp, cde_starting_pwd);
      free(tmp);
    }
  }
}

// scan through all files at top-level root directory ('/') and find if
// any of them are symlinks to DIRECTORIES.  if so, then copy the symlinks
// and their targets into CDE_ROOT_DIR, so that we can faithfully mirror the
// original filesystem (at least w.r.t. toplevel symlinks).
//
// this is necessary to ensure proper functioning
// on filesystems that have symlinks at the top level.  e.g., on Knoppix
// 2006-06-01 LiveCD, here is the top-level filesystem structure:
/*
  /
    UNIONFS/
      bin
      boot
      etc
      ...
    ramdisk/
      home/
    bin  --> /UNIONFS/bin   (symlink!)
    boot --> /UNIONFS/boot  (symlink!)
    home --> /ramdisk/home  (symlink)
    etc  --> /UNIONFS/etc   (symlink!)
    ...
    usr --> /UNIONFS/usr
*/
void CDE_create_toplevel_symlink_dirs() {
  DIR* dp = opendir("/");
  assert(dp);
  struct dirent *ep;
  while ((ep = readdir(dp))) {
    char* toplevel_abspath = format("/%s", ep->d_name); // make into abspath
    struct stat st;
    if (lstat(toplevel_abspath, &st) == 0) {
      char is_symlink = S_ISLNK(st.st_mode);
      if (is_symlink) {
        struct stat real_st;
        // only do this for top-level symlinks to DIRECTORIES
        if ((stat(toplevel_abspath, &real_st) == 0) &&
            S_ISDIR(real_st.st_mode)) {
          copy_file_into_cde_root(toplevel_abspath, cde_starting_pwd);
        }
      }
    }
    free(toplevel_abspath);
  }
  closedir(dp);
}


// create a matching symlink for filename within CDE_ROOT_DIR
// and copy over the symlink's target into CDE_ROOT_DIR as well
//
// recursively handle cases where there are symlinks to other symlinks,
// so that we need to create multiple levels of symlinks!
//
// Pre-req: filename must be an absolute path to a symlink
static void create_symlink_in_cde_root(char* filename, char* child_current_pwd) {
  char* filename_abspath = canonicalize_path(filename, child_current_pwd);

  // target file must exist, so let's resolve its name
  char* orig_symlink_target = readlink_strdup(filename_abspath);

  char* filename_abspath_copy = strdup(filename_abspath); // dirname() destroys its arg
  char* dir = dirname(filename_abspath_copy);
  char* dir_realpath = realpath_strdup(dir);
  free(filename_abspath_copy);

  char* symlink_loc_in_package = prepend_cderoot(filename_abspath);

  // make sure parent directories exist
  //mkdir_recursive(symlink_loc_in_package, 1);
  make_mirror_dirs_in_cde_package(filename_abspath, 1);

  char* symlink_target_abspath = NULL;

  // ugh, remember that symlinks can point to both absolute AND
  // relative paths ...
  if (IS_ABSPATH(orig_symlink_target)) {
    symlink_target_abspath = strdup(orig_symlink_target);

    // this is sort of tricky.  we need to insert in a bunch of ../
    // to bring the directory BACK UP to cde-root, and then we need
    // to insert in the original absolute path, in order to make the
    // symlink in the CDE package a RELATIVE path starting from
    // the cde-root/ base directory
    struct path* p = new_path_from_abspath(dir_realpath);
    char tmp[MAXPATHLEN];
    if (p->depth > 0) {
      strcpy(tmp, "..");
      int i;
      for (i = 1; i < p->depth; i++) {
        strcat(tmp, "/..");
      }
    }
    else {
      strcpy(tmp, "."); // simply use '.' if there are no nesting layers
    }
    delete_path(p);

    strcat(tmp, orig_symlink_target);

    //printf("symlink(%s, %s)\n", tmp, symlink_loc_in_package);
    symlink(tmp, symlink_loc_in_package);
  }
  else {
    symlink_target_abspath = format("%s/%s", dir_realpath, orig_symlink_target);

    // create a new identical symlink in cde-root/
    //printf("symlink(%s, %s)\n", orig_symlink_target, symlink_loc_in_package);
    symlink(orig_symlink_target, symlink_loc_in_package);
  }
  assert(symlink_target_abspath);
  assert(IS_ABSPATH(symlink_target_abspath));

  free(dir_realpath);
  free(symlink_loc_in_package);
  free(orig_symlink_target);


  struct stat symlink_target_stat;
  if (lstat(symlink_target_abspath, &symlink_target_stat)) { // lstat does NOT follow symlinks
    fprintf(stderr, "CDE WARNING: symlink_target_abspath ('%s') cannot be found\n", symlink_target_abspath);
    return; // leads to memory leak, but oh well
  }

  if (S_ISLNK(symlink_target_stat.st_mode)) {
    /* this is super nasty ... we need to handle multiple levels of
       symlinks ... yes, symlinks to symlinks!

      some programs like java are really picky about the EXACT directory
      structure being replicated within cde-package.  e.g., java will refuse
      to start unless the directory structure is perfectly mimicked (since it
      uses its true path to load start-up libraries).  this means that CDE
      Needs to be able to potentially traverse through multiple levels of
      symlinks and faithfully recreate them within cde-package.

      For example, on chongzi (Fedora Core 9):

      /usr/bin/java is a symlink to /etc/alternatives/java

      but /etc/alternatives/java is itself a symlink to /usr/lib/jvm/jre-1.6.0-openjdk/bin/java

      this example involves 2 levels of symlinks, and java requires that the
      TRUE binary to be found here in the package in order to run properly:

        /usr/lib/jvm/jre-1.6.0-openjdk/bin/java

    */
    // krazy rekursive kall!!!
    create_symlink_in_cde_root(symlink_target_abspath, child_current_pwd);
  }
  else {
    // ok, let's get the absolute path without any '..' or '.' funniness
    // MUST DO IT IN THIS ORDER, OR IT WILL EXHIBIT SUBTLE BUGS!!!
    char* symlink_dst_original_path = canonicalize_abspath(symlink_target_abspath);
    char* symlink_dst_abspath = prepend_cderoot(symlink_dst_original_path);
    //printf("  symlink_target_abspath: %s\n", symlink_target_abspath);
    //printf("  symlink_dst_abspath: %s\n\n", symlink_dst_abspath);

    if (S_ISREG(symlink_target_stat.st_mode)) {
      // base case, just hard link or copy symlink_target_abspath into symlink_dst_abspath

      // ugh, this is getting really really gross, mkdir all dirs stated in
      // symlink_dst_abspath if they don't yet exist
      //mkdir_recursive(symlink_dst_abspath, 1);
      make_mirror_dirs_in_cde_package(symlink_dst_original_path, 1);

      //printf("  cp %s %s\n", symlink_target_abspath, symlink_dst_abspath);
      // copy the target file over to cde-root/
      if ((link(symlink_target_abspath, symlink_dst_abspath) != 0) && (errno != EEXIST)) {
        copy_file(symlink_target_abspath, symlink_dst_abspath);
      }

      // if it's a shared library, then heuristically try to grep
      // through it to find whether it might dynamically load any other
      // libraries (e.g., those for other CPU types that we can't pick
      // up via strace)
      find_and_copy_possible_dynload_libs(filename, child_current_pwd);
    }
    else if (S_ISDIR(symlink_target_stat.st_mode)) { // symlink to directory
      // make sure the target directory actually exists
      //mkdir_recursive(symlink_dst_abspath, 0);
      make_mirror_dirs_in_cde_package(symlink_dst_original_path, 0);
    }
    else {
      fprintf(stderr, "CDE WARNING: create_symlink_in_cde_root('%s') has unknown target file type\n", filename);
    }

    free(symlink_dst_abspath);
    free(symlink_dst_original_path);
  }

  free(symlink_target_abspath);
  free(filename_abspath);
}

void CDE_init_tcb_dir_fields(struct tcb* tcp) {
  // malloc new entries, and then decide whether to inherit from parent
  // process entry or directly initialize
  assert(!tcp->current_dir);
  tcp->current_dir = malloc(MAXPATHLEN); // big boy!

  // if parent exists, then its fields MUST be legit, so grab them
  if (tcp->parent) {
    assert(tcp->parent->current_dir);
    strcpy(tcp->current_dir, tcp->parent->current_dir);
    //printf("inherited %s [%d]\n", tcp->current_dir, tcp->pid);

    // TODO: I don't know whether this covers all the cases of process forking ...
    if (CDE_provenance_mode) {
      printf("PROVENANCE: %u SPAWN %u\n", tcp->parent->pid, tcp->pid);
    }
  }
  else {
    // otherwise create fresh fields derived from master (cde) process
    getcwd(tcp->current_dir, MAXPATHLEN);
    //printf("fresh %s [%d]\n", tcp->current_dir, tcp->pid);
  }


  // it's possible that tcp->perceived_program_fullpath has already been
  // set, and if so, don't mess with it.  only inherit from parent if it
  // hasn't been set yet (TODO: I don't fully understand the rationale
  // for this, but it seems to work in practice so far)
  if (!tcp->perceived_program_fullpath && tcp->parent) {
    // aliased, so don't mutate or free
    tcp->perceived_program_fullpath = tcp->parent->perceived_program_fullpath;
  }
}

// find the absolute path to the cde-root/ directory, since that
// will be where our fake filesystem starts.  e.g., if our real pwd is:
//   /home/bob/cde-package/cde-root/home/alice/cool-experiment
// then the pseudo_root_dir is:
//   /home/bob/cde-package/cde-root
//
// if we're running cde-exec from outside of a cde-root/ directory,
// then try to find the cde-root/ corresponding to the location of the
// cde-exec executable
void CDE_init_pseudo_root_dir() {
  assert(CDE_exec_mode);

  struct path* p = new_path_from_abspath(cde_starting_pwd);
  assert(p->depth > 0);
  int i;
  int found_index = -1;
  for (i = 1; i <= p->depth; i++) {
    char* component = get_path_component(p, i);
    if (strcmp(component, CDE_ROOT_NAME) == 0) {
      // flag an error if there is more than one cde-root directory, since
      // we don't support NESTED cde packages o.O
      if (found_index >= 0) {
        fprintf(stderr, "Error: More than one cde-root/ directory found in pwd:\n  '%s'\n",
                cde_starting_pwd);
        exit(1);
      }

      found_index = i;
      // keep searching in case there are duplicates, in which case the
      // above assertion will fail
    }
  }

  if (found_index < 0) {
    // if we can't find 'cde-root' in cde_starting_pwd, then we must
    // be executing cde-exec from OUTSIDE of a repository, so set
    // cde_pseudo_root_dir to:
    //   dirname(readlink("/proc/self/exe")) + "/cde-root"
    char proc_self_exe[MAXPATHLEN];
    proc_self_exe[0] = '\0';
    int len = readlink("/proc/self/exe",
                       proc_self_exe, sizeof proc_self_exe);
    assert(proc_self_exe[0] != '\0');
    assert(len >= 0);
    proc_self_exe[len] = '\0'; // wow, readlink doesn't put cap on the end!

    char* toplevel_cde_root_path =
      format("%s/cde-root", dirname(proc_self_exe));

    strcpy(cde_pseudo_root_dir, toplevel_cde_root_path);

    free(toplevel_cde_root_path);
  }
  else {
    // normal case --- we're currently within a cde-root/ directory, so
    // set that as cde_pseudo_root_dir
    char* tmp = path2str(p, found_index);
    strcpy(cde_pseudo_root_dir, tmp);
    free(tmp);
  }

  delete_path(p);
}

// create a '.cde' version of the target program inside the corresponding
// location of cde_starting_pwd within CDE_ROOT_DIR, which is a
// shell script that invokes it using cde-exec
//
// also, if target_program_fullpath is only a program name
// (without any '/' chars in it, then also create a convenience script
// at the top level of the package)
//
// argv[optind] is the target program's name
void CDE_create_convenience_scripts(char** argv, int optind) {
  char* target_program_fullpath = argv[optind];

  // only take the basename to construct cde_script_name,
  // since target_program_fullpath could be a relative path like '../python'
  char* cde_script_name = format("%s.cde", basename(target_program_fullpath));
  char* progname_redirected =
    redirect_filename_into_cderoot(cde_script_name, cde_starting_pwd);

  if (progname_redirected) {
    // make sure directory exists :)
    //mkdir_recursive(progname_redirected, 1);
    make_mirror_dirs_in_cde_package(cde_starting_pwd, 0);

    // this is sort of tricky.  we need to insert in a bunch of ../ so
    // that we can find cde-exec, which is right in the cde-package directory
    struct path* p = new_path_from_abspath(cde_starting_pwd);
    char dot_dots[MAXPATHLEN];
    assert(p->depth > 0);
    strcpy(dot_dots, "..");
    int i;
    for (i = 1; i <= p->depth; i++) {
      strcat(dot_dots, "/..");
    }
    delete_path(p);

    FILE* f = fopen(progname_redirected, "w");
    fprintf(f, "#!/bin/sh\n");
    fprintf(f, "%s/cde-exec", dot_dots);
    // include original command-line options
    for (i = 1; i < optind; i++) {
      fprintf(f, " '%s'", argv[i]);
    }
    // double quotes seem to work well for making $@ more accurate
    fprintf(f, " '%s' \"$@\"\n", target_program_fullpath);
    fclose(f);

    chmod(progname_redirected, 0777); // now make the script executable

    free(progname_redirected);
  }

  if (!strchr(target_program_fullpath, '/')) {
    char* toplevel_script_name = format("%s/%s", CDE_PACKAGE_DIR, cde_script_name);
    FILE* f = fopen(toplevel_script_name, "w");
    fprintf(f, "#!/bin/sh\n");
    fprintf(f, "cd cde-root && ../cde-exec");

    // include original command-line options
    int i;
    for (i = 1; i < optind; i++) {
      fprintf(f, " '%s'", argv[i]);
    }
    // double quotes seem to work well for make $@ more accurate
    fprintf(f, " '%s' \"$@\"\n", target_program_fullpath);

    fclose(f);
    chmod(toplevel_script_name, 0777); // now make the script executable
    free(toplevel_script_name);
  }

  free(cde_script_name);
}


static void _add_to_array_internal(char** my_array, int* p_len, char* p, char* array_name) {
  assert(my_array[*p_len] == NULL);
  my_array[*p_len] = strdup(p);

  // debug printf
  //fprintf(stderr, "%s[%d] = '%s'\n", array_name, *p_len, my_array[*p_len]);

  (*p_len)++;

  if (*p_len >= 100) {
    fprintf(stderr, "Fatal error: more than 100 entries in %s\n", array_name);
    exit(1);
  }
}

void CDE_add_ignore_exact_path(char* p) {
  _add_to_array_internal(ignore_exact_paths, &ignore_exact_paths_ind, p, "ignore_exact_paths");
}

void CDE_add_ignore_prefix_path(char* p) {
  _add_to_array_internal(ignore_prefix_paths, &ignore_prefix_paths_ind, p, "ignore_prefix_paths");
}

void CDE_add_ignore_substr_path(char* p) {
  _add_to_array_internal(ignore_substr_paths, &ignore_substr_paths_ind, p, "ignore_substr_paths");
}

void CDE_add_redirect_exact_path(char* p) {
  _add_to_array_internal(redirect_exact_paths, &redirect_exact_paths_ind, p, "redirect_exact_paths");
}

void CDE_add_redirect_prefix_path(char* p) {
  _add_to_array_internal(redirect_prefix_paths, &redirect_prefix_paths_ind, p, "redirect_prefix_paths");
}

void CDE_add_redirect_substr_path(char* p) {
  _add_to_array_internal(redirect_substr_paths, &redirect_substr_paths_ind, p, "redirect_substr_paths");
}

void CDE_add_ignore_envvar(char* p) {
  _add_to_array_internal(ignore_envvars, &ignore_envvars_ind, p, "ignore_envvars");
}


// initialize arrays based on the cde.options file, which has the grammar:
//
// ignore_exact=<exact path to ignore>
// ignore_prefix=<path prefix to ignore>
// ignore_substr=<path substring to ignore>
// redirect_exact=<exact path to allow>
// redirect_prefix=<path prefix to allow>
// redirect_substr=<path substring to allow>
// ignore_environment_var=<environment variable to ignore>
void CDE_init_options() {
  memset(ignore_exact_paths,    0, sizeof(ignore_exact_paths));
  memset(ignore_prefix_paths,   0, sizeof(ignore_prefix_paths));
  memset(ignore_substr_paths,   0, sizeof(ignore_substr_paths));
  memset(redirect_exact_paths,  0, sizeof(redirect_exact_paths));
  memset(redirect_prefix_paths, 0, sizeof(redirect_prefix_paths));
  memset(redirect_substr_paths, 0, sizeof(redirect_substr_paths));
  memset(ignore_envvars,        0, sizeof(ignore_envvars));

  ignore_exact_paths_ind = 0;
  ignore_prefix_paths_ind = 0;
  ignore_substr_paths_ind = 0;
  redirect_exact_paths_ind = 0;
  redirect_prefix_paths_ind = 0;
  redirect_substr_paths_ind = 0;
  ignore_envvars_ind = 0;


  FILE* f = NULL;

  if (CDE_exec_mode) {
    // look for a cde.options file in $CDE_PACKAGE_DIR

    // you must run this AFTER running CDE_init_pseudo_root_dir()
    assert(*cde_pseudo_root_dir);
    char* options_file = format("%s/../cde.options", cde_pseudo_root_dir);
    f = fopen(options_file, "r");
    free(options_file);
  }
  else {
    // look for a cde.options file in pwd
    f = fopen("cde.options", "r");

    // if found, copy it into the package
    if (f) {
      copy_file("cde.options", CDE_PACKAGE_DIR "/cde.options");
    }
  }

  if (!f) {
    fprintf(stderr, "Fatal error: missing cde.options file\n");
    exit(1);
  }


  char is_first_line = 1;

  char* line = NULL;
  size_t len = 0;
  ssize_t read;
  while ((read = getline(&line, &len, f)) != -1) {
    assert(line[read-1] == '\n');
    line[read-1] = '\0'; // strip of trailing newline

    // make sure there's an appropriate version number on first line
    if (is_first_line) {
      if (strncmp(line, CDE_OPTIONS_VERSION_NUM, strlen(CDE_OPTIONS_VERSION_NUM)) != 0) {
        fprintf(stderr, "Error: cde.options file incompatible with this version of cde ('%s')\n",
                CDE_OPTIONS_VERSION_NUM);
        exit(1);
      }
      is_first_line = 0;
      continue;
    }

    // ignore blank or comment lines
    if (line[0] == '\0' || line[0] == '#') {
      continue;
    }

    char* p;
    char is_first_token = 1;
    char set_id = -1;

    for (p = strtok(line, "="); p; p = strtok(NULL, "=")) {
      if (is_first_token) {
        if (strcmp(p, "ignore_exact") == 0) {
          set_id = 1;
        }
        else if (strcmp(p, "ignore_prefix") == 0) {
          set_id = 2;
        }
        else if (strcmp(p, "ignore_environment_var") == 0) {
          set_id = 3;
        }
        else if (strcmp(p, "redirect_exact") == 0) {
          set_id = 4;
        }
        else if (strcmp(p, "redirect_prefix") == 0) {
          set_id = 5;
        }
        else if (strcmp(p, "ignore_substr") == 0) {
          set_id = 6;
        }
        else if (strcmp(p, "redirect_substr") == 0) {
          set_id = 7;
        }
        else {
          fprintf(stderr, "Fatal error in cde.options: unrecognized token '%s'\n", p);
          exit(1);
        }

        is_first_token = 0;
      }
      else {
        switch (set_id) {
          case 1:
            CDE_add_ignore_exact_path(p);
            break;
          case 2:
            CDE_add_ignore_prefix_path(p);
            break;
          case 3:
            CDE_add_ignore_envvar(p);
            break;
          case 4:
            CDE_add_redirect_exact_path(p);
            break;
          case 5:
            CDE_add_redirect_prefix_path(p);
            break;
          case 6:
            CDE_add_ignore_substr_path(p);
            break;
          case 7:
            CDE_add_redirect_substr_path(p);
            break;
          default:
            assert(0);
        }

        break;
      }
    }
  }

  fclose(f);

  cde_options_initialized = 1;
}


void CDE_load_environment_vars() {
  static char cde_full_environment_abspath[MAXPATHLEN];
  strcpy(cde_full_environment_abspath, cde_pseudo_root_dir);
  strcat(cde_full_environment_abspath, "/../cde.full-environment");

  struct stat env_file_stat;
  if (stat(cde_full_environment_abspath, &env_file_stat)) {
    perror(cde_full_environment_abspath);
    exit(1);
  }

  int full_environment_fd = open(cde_full_environment_abspath, O_RDONLY);

  void* environ_start =
    (char*)mmap(0, env_file_stat.st_size, PROT_READ, MAP_PRIVATE, full_environment_fd, 0);

  char* environ_str = (char*)environ_start;
  while (*environ_str) {
    int environ_strlen = strlen(environ_str);

    // format: "name=value"
    // note that 'value' might itself contain '=' characters,
    // so only split on the FIRST '='

    char* cur = strdup(environ_str); // strtok needs to mutate
    char* name = NULL;
    char* val = NULL;

    int count = 0;
    char* p;
    int start_index_of_value = 0;

    // strtok is so dumb!!!  need to munch through the entire string
    // before it restores the string to its original value
    for (p = strtok(cur, "="); p; p = strtok(NULL, "=")) {
      if (count == 0) {
        name = strdup(p);
      }
      else if (count == 1) {
        start_index_of_value = (p - cur);
      }

      count++;
    }

    if (start_index_of_value) {
      val = strdup(environ_str + start_index_of_value);
    }

    // make sure we're not ignoring this environment var:
    int i;
    int ignore_me = 0;
    for (i = 0; i < ignore_envvars_ind; i++) {
      if (strcmp(name, ignore_envvars[i]) == 0) {
        ignore_me = 1;
        break;
      }
    }

    // ignore an invalid variable with an empty name or a name
    // that's simply a newline character (some files have a trailing
    // newline, which strtok picks up, ugh):
    if (!name || (strcmp(name, "\n") == 0)) {
      ignore_me = 1;
    }

    if (!ignore_me) {
      // subtle ... if val is NULL, then we should call setenv() with
      // an empty string as val, NOT a NULL, since calling it with a
      // NULL parameter will cause it to DELETE the environment
      // variable, not set it to ""
      if (val) {
        setenv(name, val, 1);
      }
      else {
        setenv(name, "", 1);
      }
    }
    else {
      if (CDE_verbose_mode) {
        printf("ignored envvar '%s' => '%s'\n", name, val);
      }
    }

    if (name) free(name);
    if (val) free(val);
    free(cur);

    // every string in cde_full_environment_abspath is
    // null-terminated, so this advances to the next string
    environ_str += (environ_strlen + 1);
  }

  munmap(environ_start, env_file_stat.st_size);
  close(full_environment_fd);
}


// if we're running in CDE_exec_mode, redirect path argument for bind()
// and connect() into cde-root sandbox
void CDE_begin_socket_bind_or_connect(struct tcb *tcp) {
  // only do this redirection in CDE_exec_mode
  if (!CDE_exec_mode) {
    return;
  }

  // code adapted from printsock in strace-4.5.20/net.c
  long addr = tcp->u_arg[1];
  int addrlen = tcp->u_arg[2];
 
  union {
    char pad[128];
    struct sockaddr sa;
    struct sockaddr_un sau;
  } addrbuf;

  if (addr == 0) {
    return;
  }

  if (addrlen < 2 || addrlen > sizeof(addrbuf)) {
    addrlen = sizeof(addrbuf);
  }

  memset(&addrbuf, 0, sizeof(addrbuf));
  if (umoven(tcp, addr, addrlen, addrbuf.pad) < 0) {
    return;
  }
  addrbuf.pad[sizeof(addrbuf.pad) - 1] = '\0';

  /* AF_FILE is also a synonym for AF_UNIX */
  if (addrbuf.sa.sa_family == AF_UNIX) {
    if (addrlen > 2 && addrbuf.sau.sun_path[0]) {
      //tprintf("path=");

      // addr + sizeof(addrbuf.sau.sun_family) is the location of the real path
      char* original_path = strcpy_from_child(tcp, addr + sizeof(addrbuf.sau.sun_family));
      if (original_path) {
        //printf("original_path='%s'\n", original_path);

        char* redirected_path =
          redirect_filename_into_cderoot(original_path, tcp->current_dir);

        // could be null if path is being ignored by cde.options
        if (redirected_path) {
          //printf("redirected_path: '%s'\n", redirected_path);

          unsigned long new_pathlen = strlen(redirected_path);

          // alter the socket address field to point to redirected path
          memcpy_to_child(tcp->pid, (char*)(addr + sizeof(addrbuf.sau.sun_family)),
                          redirected_path, new_pathlen + 1);

          free(redirected_path);


          // remember the 2 extra bytes for the sun_family field!
          unsigned long new_totallen = new_pathlen + sizeof(addrbuf.sau.sun_family);

          struct user_regs_struct cur_regs;
          EXITIF(ptrace(PTRACE_GETREGS, tcp->pid, NULL, (long)&cur_regs) < 0);

#if defined (I386)
          // on i386, things are tricky tricky!
          // the kernel uses socketcall() as a common entry
          // point for all socket-related system calls
          // http://www.kernel.org/doc/man-pages/online/pages/man2/socketcall.2.html
          //
          // the ecx register contains a pointer to an array of 3 pointers
          // (of size 'unsigned long'), which represents the 3 arguments
          // to the bind/connect syscall.  they are:
          //   arg[0] - socket number
          //   arg[1] - pointer to socket address structure
          //   arg[2] - length of socket address structure

          // we need to alter the length field to new_totallen,
          // which is VERY IMPORTANT or else the path that the
          // kernel sees will be truncated!!!

          // we want to override arg[2], which is located at:
          //   cur_regs.ecx + 2*sizeof(unsigned long)
          memcpy_to_child(tcp->pid, cur_regs.ecx + 2*sizeof(unsigned long),
                          &new_totallen, sizeof(unsigned long));
#elif defined(X86_64)
          // on x86-64, things are much simpler.  the length field is
          // stored in %rdx (the third argument), so simply override
          // that register with new_totallen
          cur_regs.rdx = (long)new_totallen;
          ptrace(PTRACE_SETREGS, tcp->pid, NULL, (long)&cur_regs);
#else
          #error "Unknown architecture (not I386 or X86_64)"
#endif
        }

        free(original_path);
      }
    }
  }
}

