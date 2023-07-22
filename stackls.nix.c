#define __STDC_WANT_IEC_60559_BFP_EXT__
#include <alloca.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TRUE 1

#define PROG_NAME stackls
#define PROG_LICENSE 2023 Chuback Bidpaa, Unlicense
#define PROG_USAGE                                                            \
  Usage:                                                                      \
  stackls [-o outpath] PID
#define PROG_EXAMPLE                                                          \
  Example:                                                                    \
  stackls 24212
#define PROG_HINT                                                             \
  You may pass a filepath as output.Need not exit.Otherwise,                  \
      prints to stdout.You can also redirect the PID via stdin, however,      \
      then, the arguments will not be working.

#ifndef LINESIZE_MAX
#define LINESIZE_MAX 4096
#endif

#ifndef OUTPUT_FMT
#define OUTPUT_FMT "[%lu] %s\n"
#endif

#if !defined(__linux__) || !defined(__linux) || !defined(__linux)             \
    || !defined(__gnu_linux__)
#warning "Compliant predefined CPP macros not detected."
#warning                                                                      \
    "This code is designed to be compiled and ran under the GNU Linux operating system."
#warning "A Microsoft Windows version is provided."
#endif

#ifdef __GNUC__
#define _normal_inline static inline __attribute__ ((always_inline))
#define _hotbed_inline static inline __attribute__ ((always_inline, hot))
#define _coldbed_inline static inline __attribute__ ((always_inline, cold))
#define _fn_metadata file __FILE__, line __LINE__
#else
#define _normal_inline static inline
#define _hotbed_inline static inline
#define _coldbed_inline static inline
#define _fn_metadata function __func__, file __FILE__, line __LINE__
#endif

#define _static_func static

#define _str_raw(...) #__VA_ARGS__
#define STR(...) _str_raw (__VA_ARGS__)
#define STR_LF(...) STR (__VA_ARGS__ \n)

#define _mmap(FD, OFFSET)                                                     \
  mmap (NULL, MMAP_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE, FD, OFFSET)

#define errno_CHECK(CLOSURE, CALL)                                            \
  do                                                                          \
    {                                                                         \
      if (((long)(CLOSURE)) < 0)                                              \
        {                                                                     \
          fprintf (stderr, "Error at function %s:\n", __PRETTY_FUNCTION__);   \
          perror (STR (CALL at _fn_metadata));                                \
          exit (EXIT_FAILURE);                                                \
        }                                                                     \
    }                                                                         \
  while (0)

#define CHECK_PROCID(PROCID, TMPCHR)                                          \
  do                                                                          \
    {                                                                         \
      TMPCHR = *PROCID++;                                                     \
      if (!isdigit (TMPCHR) && TMPCHR)                                        \
        {                                                                     \
          fprintf (stderr, STR_LF (Invalid process id, pass `--help`));       \
          exit (EXIT_FAILURE);                                                \
        }                                                                     \
    }                                                                         \
  while (TMPCHR)

#define CTX_stracefname slsctx->strace_fname
#define CTX_previousline slsctx->previous_line
#define CTX_previousfunction slsctx->previous_func
#define CTX_stackcounter slsctx->stack_stackcounter
#define CTX_inputstream slsctx->input_stream
#define CTX_outputstream slsctx->output_stream
#define CTX_eofstate slsctx->reached_eof
#define CTX_outpath slsctx->outputfile_name
#define CTX_procidstr slsctx->process_id_str
#define CTX_procidint slsctx->process_id_int

typedef struct
{
  uint8_t strace_fname[FILENAME_MAX];
  uint8_t previous_line[LINESIZE_MAX];
  uint8_t *previous_func;
  FILE *input_stream;
  FILE *output_stream;
  size_t stack_stackcounter;
  int reached_eof;
  pid_t process_id_int;
  char *process_id_str;
  char *outputfile_name;
} stackls_t;

_coldbed_inline void
stackls_parse_procid_str (stackls_t *slsctx)
{
  errno_CHECK (CTX_procidint = (pid_t)strtoll (CTX_procidstr, NULL, 10),
               strtoll);
}

_coldbed_inline void
stackls_get_strace_filename (stackls_t *slsctx)
{
  errno_CHECK (sprintf (&CTX_stracefname[0], "/proc/%s/stack", CTX_procidstr),
               sprintf);
}

_coldbed_inline void
stackls_open_strace_fstream (stackls_t *slsctx)
{
  errno_CHECK (CTX_inputstream = fopen (&CTX_stracefname[0], "r"), fopen);
}

_coldbed_inline void
stackls_open_output_fstream (stackls_t *slsctx)
{
  if (CTX_outputstream != stdout)
    errno_CHECK (CTX_outputstream = fopen (&CTX_outpath[0], "w"), fopen);
  else
    CTX_outputstream = stdout;
}

_coldbed_inline void
stackls_close_input_fstream (stackls_t *slsctx)
{
  fclose (CTX_inputstream);
}

_coldbed_inline void
stackls_close_output_stream (stackls_t *slsctx)
{
  errno_CHECK (fprintf (CTX_outputstream, "\n"), fprintf);
  if (CTX_outputstream != stdout)
    fclose (CTX_outputstream);
}

_hotbed_inline void
stackls_read_strace_line (stackls_t *slsctx)
{
  char cchr;
  size_t top = 0;
  fgetc (CTX_inputstream);
  memset (&CTX_previousline[0], 0, LINESIZE_MAX);
  while ((cchr = fgetc (CTX_inputstream)) != '\n')
    {
      if (cchr == EOF)
        {
          CTX_eofstate = TRUE;
          return;
        }
      CTX_previousline[top++] = cchr;
    }
}

_hotbed_inline void
stackls_parse_strace_line (stackls_t *slsctx)
{
  size_t plus_offset, space_offset;
  errno_CHECK (space_offset = strcspn ((char *)&CTX_previousline[0], " "),
               strcspn);
  errno_CHECK (plus_offset = strcspn ((char *)&CTX_previousline[0], "+"),
               strcspn);

  CTX_previousline[plus_offset] = '\0';
  CTX_previousfunction = &CTX_previousline[space_offset++];
}

_normal_inline void
stackls_print_strace_line (stackls_t *slsctx)
{
  if (!CTX_eofstate)
    {
      size_t new_count = CTX_stackcounter++;
      errno_CHECK (fprintf (CTX_outputstream, OUTPUT_FMT, new_count,
                            CTX_previousfunction),
                   fprintf);
    }
}

_hotbed_inline void
stackls_main_iterative_procedure (stackls_t *slsctx)
{
  stackls_get_strace_filename (slsctx);
  stackls_parse_procid_str (slsctx);
  stackls_open_strace_fstream (slsctx);
  stackls_open_output_fstream (slsctx);

  while (!CTX_eofstate)
    {
      stackls_read_strace_line (slsctx);
      stackls_parse_strace_line (slsctx);
      stackls_print_strace_line (slsctx);
    }

  stackls_close_output_stream (slsctx);
  stackls_close_input_fstream (slsctx);
}

_static_func void
display_help ()
{
  fprintf (stdout, STR_LF (PROG_NAME PROG_LICENSE));
  fprintf (stdout, STR_LF (PROG_USAGE));
  fprintf (stdout, STR_LF (PROG_EXAMPLE));
  fprintf (stdout, STR_LF (PROG_HINT));
  fprintf (stdout, STR_LF ());
  exit (EXIT_SUCCESS);
}

_static_func void
parse_arguments (int argc, char **argv, stackls_t *slsctx)
{
  if (argc == 1)
    display_help ();
  else if (argc == 2)
    {
      char c, *arg2 = argv[1];
      if (!strncmp (arg2, "--help", 6) || !strncmp (arg2, "-h", 2))
        display_help ();
      else
        {
          CHECK_PROCID (arg2, c);
          CTX_procidstr = argv[1];
          CTX_outputstream = stdout;
        }
    }
  else if (argc == 4)
    {
      char c, *arg2 = argv[1], *arg4 = argv[3];
      if (strncmp (arg2, "-o", 2))
        {
          fprintf (stderr, STR_LF (Wrong arguments, pass in `--help`));
          exit (EXIT_FAILURE);
        }
      CHECK_PROCID (arg4, c);
      CTX_procidstr = argv[3];
      CTX_outpath = argv[2];
    }
  else
    {
      display_help ();
    }
}

_static_func void
parse_stdin (stackls_t *slsctx)
{
  char c, *pidstr = CTX_procidstr;
  CTX_procidstr = alloca (INT_WIDTH);
  fscanf (stdin, "%s", CTX_procidstr);
  CHECK_PROCID (pidstr, c);
}

int
main (int argc, char **argv)
{
  stackls_t slsctx;
  memset (&slsctx, 0, sizeof (stackls_t));
  if (!isatty (fileno (stdin)))
    {
      parse_stdin (&slsctx);
    }
  else
    {
      parse_arguments (argc, argv, &slsctx);
    }
  stackls_main_iterative_procedure (&slsctx);
}