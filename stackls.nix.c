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

#include "stackls.com.h"
#include "stackls.nix.h"

void
stackls_parse_procid_str (stackls_t *slsctx)
{
  nixerror_CHECK (CTX_ProcessIdInt = (pid_t)strtoll (CTX_ProcessIdStr, NULL, 10),
               strtoll);
}

void
stackls_get_strace_filename (stackls_t *slsctx)
{
  nixerror_CHECK (
      sprintf (&CTX_StraceFileName[0], "/proc/%s/stack", CTX_ProcessIdStr),
      sprintf);
}

void
stackls_open_strace_fstream (stackls_t *slsctx)
{
  nixerror_CHECK (CTX_InputStream = fopen (&CTX_StraceFileName[0], "r"), fopen);
}

void
stackls_open_output_fstream (stackls_t *slsctx)
{
  if (CTX_OutputStream != stdout)
    nixerror_CHECK (CTX_OutputStream = fopen (&CTX_OutPath[0], "w"), fopen);
  else
    CTX_OutputStream = stdout;
}

void
stackls_close_input_fstream (stackls_t *slsctx)
{
  fclose (CTX_InputStream);
}

void
stackls_close_output_stream (stackls_t *slsctx)
{
  nixerror_CHECK (fprintf (CTX_OutputStream, "\n"), fprintf);
  if (CTX_OutputStream != stdout)
    fclose (CTX_OutputStream);
}

void
stackls_read_strace_line (stackls_t *slsctx)
{
  char cchr;
  size_t top = 0;
  fgetc (CTX_InputStream);
  memset (&CTX_PreviousLine[0], 0, LINESIZE_MAX);
  while ((cchr = fgetc (CTX_InputStream)) != '\n')
    {
      if (cchr == EOF)
        {
          CTX_EOFReached = TRUE;
          return;
        }
      CTX_PreviousLine[top++] = cchr;
    }
}

_hotbed_inline void
stackls_parse_strace_line (stackls_t *slsctx)
{
  size_t plus_offset, space_offset;
  nixerror_CHECK (space_offset = strcspn ((char *)&CTX_PreviousLine[0], " "),
               strcspn);
  nixerror_CHECK (plus_offset = strcspn ((char *)&CTX_PreviousLine[0], "+"),
               strcspn);

  CTX_PreviousLine[plus_offset] = '\0';
  CTX_PreviousFunc = &CTX_PreviousLine[space_offset++];
}

void
stackls_print_strace_line (stackls_t *slsctx)
{
  if (!CTX_EOFReached)
    {
      size_t new_count = CTX_StackCounter++;
      nixerror_CHECK (
          fprintf (CTX_OutputStream, OUTPUT_FMT, new_count, CTX_PreviousFunc),
          fprintf);
    }
}

void
stackls_main_iterative_procedure (stackls_t *slsctx)
{
  stackls_get_strace_filename (slsctx);
  stackls_parse_procid_str (slsctx);
  stackls_open_strace_fstream (slsctx);
  stackls_open_output_fstream (slsctx);

  while (!CTX_EOFReached)
    {
      stackls_read_strace_line (slsctx);
      stackls_parse_strace_line (slsctx);
      stackls_print_strace_line (slsctx);
    }

  stackls_close_output_stream (slsctx);
  stackls_close_input_fstream (slsctx);
}

void
display_help ()
{
  fprintf (stdout, STR_LF (PROG_NAME PROG_LICENSE));
  fprintf (stdout, STR_LF (PROG_USAGE));
  fprintf (stdout, STR_LF (PROG_EXAMPLE));
  fprintf (stdout, STR_LF (PROG_HINT));
  fprintf (stdout, STR_LF ());
  exit (EXIT_SUCCESS);
}

void
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
          CTX_ProcessIdStr = argv[1];
          CTX_OutputStream = stdout;
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
      CTX_ProcessIdStr = argv[3];
      CTX_OutPath = argv[2];
    }
  else
    {
      display_help ();
    }
}

void
parse_stdin (stackls_t *slsctx)
{
  char c, *pidstr = CTX_ProcessIdStr;
  CTX_ProcessIdStr = alloca (INT_WIDTH);
  fscanf (stdin, "%s", CTX_ProcessIdStr);
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