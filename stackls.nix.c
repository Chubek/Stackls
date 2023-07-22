#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/mman.h>

#ifndef MMAP_SIZE
#define MMAP_SIZE 1025
#endif

#ifndef FUNCNAME_MAX
#define FUNCNAME_MAX 2049
#endif

#ifndef OUTPUT_FMT
#define OUTPUT_FMT "[%lu] %s\n"
#endif

#ifndef PID_NDIGITS
#define PID_NDIGITS 22
#endif

#if !defined(__linux__) || !defined(__linux) || !defined(__linux) || !defined(__gnu_linux__)
#warning "Compliant predefined CPP macros not detected."
#warning "This code is designed to be compiled and ran under the GNU Linux operating system."
#warning "A Microsoft Windows version is provided."
#endif

#ifdef __GNUC__
#define _normal_inline static inline __attribute__((always_inline))
#define _hotbed_inline static inline __attribute__((always_inline, hot))
#define _coldbed_inline static inline __attribute__((always_inline, cold))
#define _fn_metadata function __PRETTY_FUNCTION__, file __FILE__, line __LINE__
#else
#define _normal_inline static inline
#define _hotbed_inline static inline
#define _coldbed_inline static inline
#define _fn_metadata function __func__, file __FILE__, line __LINE__
#endif

#define _static_func static

#define _str_raw(...) #__VA_ARGS__
#define STR(...) _str_raw(__VA_ARGS__)
#define STR_LF(...) STR(__VA_ARGS__ \n)

#define _mmap(FD, OFFSET) mmap(NULL, MMAP_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE, FD, OFFSET)

#define errno_CHECK(CLOSURE, CALL)				\
	do {										\
		if (((long)(CLOSURE)) < 0) {			\
			perror(STR(MSG at _fn_metadata));	\
			exit(EXIT_FAILURE);					\
		}										\
	} while (0)

#define CTX_pfsname slsctx->procfs_name
#define CTX_pfsmmap slsctx->procfs_mmap
#define CTX_pfsfdsc slsctx->procfs_fdesc
#define CTX_pfsoffs slsctx->procfs_offset
#define CTX_lastfnm slsctx->last_fnname
#define CTX_procidn slsctx->process_id
#define CTX_procids slsctx->procid_str
#define CTX_counter slsctx->stack_counter
#define CTX_outstrm slsctx->output_stream
#define CTX_eofstat slsctx->reached_eof
#define CTX_outpath slsctx->outputfile_name

typedef struct {
	uint8_t procfs_name[FILENAME_MAX];
	uint8_t last_fnname[FUNCNAME_MAX];
	FILE *output_stream;
	pid_t process_id;
	int procfs_fdesc;
	uint8_t *procfs_mmap;
	size_t procfs_offset;
	size_t stack_counter;
	int8_t reached_eof;
	char *procid_str;
	char *outputfile_name;
} stackls_t;


_normal_inline void
stackls_get_procfs_filename(stackls_t *slsctx) {
	errno_CHECK(sprintf(&CTX_pfsname[0], "/proc/%d/stack", CTX_procidn), sprintf);
}

_normal_inline void
stackls_open_procfs_filedesc(stackls_t *slsctx) {
	errno_CHECK(open(&CTX_pfsname[0], O_RDONLY), open);
}

_coldbed_inline void
stackls_parse_procid_str(stackls_t *slsctx) {
	errno_CHECK(CTX_procidn = (pid_t)strtoll(&CTX_procids[0], 10, NULL), strtoll);
}

_coldbed_inline void
stackls_open_output_stream(stackls_t *slsctx) {
	if (CTX_outstrm != stdout)
		errno_CHECK(CTX_outstrm = fopen(&CTX_outpath[0], "w"), fopen);
	else
		CTX_outstrm = stdout;
}

_coldbed_inline void
stackls_close_procfs_filedesc(stackls_t *slsctx) {
	close(CTX_pfsfdsc);
}

_coldbed_inline void
stackls_close_output_stream(stackls_t *slsctx) {
	errno_CHECK(fprintf(CTX_outstrm, "\n"), fprintf);
	if (CTX_outstrm != stdout)
		fclose(CTX_outstrm);
}

_normal_inline void
stackls_check_procfs_eof(stackls_t *slsctx) {
	CTX_eofstat = lseek(CTX_pfsfdsc, SEEK_SET, CTX_pfsoffs + UCHAR_WIDTH) < 0;
}

_normal_inline void
stackls_mmap_procfs_offset(stackls_t *slsctx) {
	errno_CHECK(CTX_pfsmmap = (uint8_t*)_mmap(CTX_pfsfdsc, CTX_pfsoffs), mmap);
}

_normal_inline void
stackls_unmap_procfs_mmap(stackls_t *slsctx) {
	errno_CHECK(munmap(CTX_pfsmmap, MMAP_SIZE), munmap);
}

_hotbed_inline void
stackls_read_procfs_mmap(stackls_t *slsctx) {
	size_t linefeed_offset, plus_offset, space_offset, fnname_len;	
	
	errno_CHECK(memset(&CTX_lastfnm[0], 0, FUNCNAME_MAX), memset);

	errno_CHECK(linefeed_offset = strcpn((char*)CTX_pfsmmap, "\n"), strcspn);
	errno_CHECK(space_offset = strcpn((char*)CTX_pfsmmap, " "), strcspn);
	errno_CHECK(plus_offset = strcpn((char*)CTX_pfsmmap, "+"), strcspn);

	fnname_len = plus_offset - space_offset;
	CTX_pfsoffs += ++linefeed_offset;
	errno_CHECK(memmove((void*)&CTX_lastfnm[0], (void*)CTX_pfsmmap[space_offset + 1], plus_offset - space_offset), memmove);
}

_normal_inline void
stackls_print_last_fnname(stackls_t *slsctx) {
	size_t new_count = CTX_counter++;
	errno_CHECK(fprintf(CTX_outstrm, OUTPUT_FMT, new_count, CTX_lastfnm), fprintf);
}

_static_func void
stackls_main_iterative_procedure(stackls_t *slsctx) {
	stackls_parse_procid_str(slsctx);
	stackls_get_procfs_filename(slsctx);
	stackls_open_procfs_filedesc(slsctx)
	stackls_open_output_stream(slsctx);

	while(!CTX_eofstat) {
		stackls_mmap_procfs_offset(slsctx);
		stackls_read_procfs_mmap(slsctx);
		stackls_print_last_fnname(slsctx);
		stackls_unmap_procfs_mmap(slsctx);
		stackls_check_procfs_eof(slsctx);
	}

	stackls_close_output_stream(slsctx);
	stackls_close_procfs_filedesc(slsctx);
}

#define PROG_NAME stackls
#define PROG_LICENSE 2023 Chuback Bidpaa, Unlicense
#define PROG_USAGE Usage: stackls [-o outpath] PID
#define PROG_EXAMPLE Example: stackls 24212
#define PROG_HINT You may pass a filepath as output. Need not exit. Otherwise, prints to stdout.

#define CHECK_PROCID(PROCID, TMPCHR)				\
	while ((TMPCHR = *PROCID++)) {				\
		if (!isdigit(TMPCHR)) {					\
			fprintf(stderr, STR_LF(Invalid process id, type --help));		\
			exit(EXIT_FAILURE)		\
		}	\
	}

_static_func void
display_help() {
	fprintf(stdout, STR_LF(PROG_NAME PROG_LICENSE));
	fprintf(stdout, STR_LF(PROG_USAGE));
	fprintf(stdout, STR_LF(PROG_EXAMPLE));
	fprintf(stdout, STR_LF(PROF_HINT));
	fprintf(stdout, STR_LF());
	exit(EXIT_SUCCESS);
}

static_func void
parse_arguments(int argc, char **argv, stackls_t *slsctx) {
	if (argc == 1)
		display_help();
	else if (argc == 2) {
		char c, *arg2 = argv[1];
		if (!strncmp(arg2, "--help", 6) || !strncmp(arg2, "-h", 2))
			display_help();
		else {
			CHECK_PROCID(arg2, c);
			CTX_procids = arg2;
			CTX_outstrm = stdout;
		}
	} else if (argc == 4) {
		char c, *arg2 = argv[1], *arg3 = argv[2], *arg4 = argv[3];
		if (strncmp(arg2, "-o", 2)) {
			fprintf(stderr, STR_LF(Wrong arguments, type --help));
			exit(EXIT_FAILURE);
		}
		CHECK_PROCID(arg4, c);
		CTX_procids = arg4;
		CTX_outpath = arg3;
	} else {
		display_help();
	}

} 

int main(int argc, char **argv) {
	stackls_t slsctx;
	parse_arguments(argc, argv, &slsctx);
	stackls_main_iterative_procedure(&slsctx);
}