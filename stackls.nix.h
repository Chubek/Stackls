#ifndef STACKLS_LINUX_H
#define STACKLS_LINUX_H

#define TRUE 1
#define FALSE 0

#ifndef LINESIZE_MAX
#define LINESIZE_MAX 4096
#endif

#ifndef OUTPUT_FMT
#define OUTPUT_FMT "[%lu] %s\n"
#endif

#define _mmap(FD, OFFSET)                                                     \
  mmap (NULL, MMAP_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE, FD, OFFSET)

#define nixerror_CHECK(CLOSURE, CALL)                                         \
  do                                                                          \
    {                                                                         \
      if (((long)(CLOSURE)) < 0)                                              \
        {                                                                     \
          fprintf (stderr, "Error at function %s:\n", _fn_name);              \
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

#define CTX_StraceFileName slsctx->strace_fname
#define CTX_PreviousLine slsctx->previous_line
#define CTX_PreviousFunc slsctx->previous_func
#define CTX_StackCounter slsctx->stack_counter
#define CTX_InputStream slsctx->input_stream
#define CTX_OutputStream slsctx->output_stream
#define CTX_EOFReached slsctx->reached_eof
#define CTX_OutPath slsctx->outputfile_name
#define CTX_ProcessIdStr slsctx->process_id_str
#define CTX_ProcessIdInt slsctx->process_id_int

typedef struct
{
  uint8_t strace_fname[FILENAME_MAX], previous_line[LINESIZE_MAX];
  char *process_id_str, *outputfile_name;
  FILE *input_stream, *output_stream;
  uint8_t *previous_func;
  size_t stack_counter;
  pid_t process_id_int;
  int reached_eof;
} stackls_t;


_coldbed_inline void
stackls_parse_procid_str (stackls_t *slsctx);

_coldbed_inline void
stackls_get_strace_filename (stackls_t *slsctx);

_coldbed_inline void
stackls_open_strace_fstream (stackls_t *slsctx);

_coldbed_inline void
stackls_open_output_fstream (stackls_t *slsctx);

_coldbed_inline void
stackls_close_input_fstream (stackls_t *slsctx);

_coldbed_inline void
stackls_close_output_stream (stackls_t *slsctx);

_hotbed_inline void
stackls_read_strace_line (stackls_t *slsctx);

_normal_inline void
stackls_print_strace_line (stackls_t *slsctx);

_hotbed_inline void
stackls_main_iterative_procedure (stackls_t *slsctx);

_static_func void
display_help ();

_static_func void
parse_arguments (int argc, char **argv, stackls_t *slsctx);

_static_func void
parse_stdin (stackls_t *slsctx);








#endif