#ifndef STACKLS_COMMON_H
#define STACKLS_COMMON_H

#define PROG_NAME stackls
#define PROG_LICENSE 2023 Chuback Bidpaa, Unlicense
#define PROG_USAGE                                                            \
  Usage:                                                                      \
  stackls[-o OutPath] PID
#define PROG_EXAMPLE                                                          \
  Example:                                                                    \
  stackls 24212
#define PROG_HINT                                                             \
  You may pass a filepath as output.Need not exit.Otherwise,                  \
      prints to stdout.You can also redirect the PID via stdin, however,      \
      then, the arguments will not be working.


#ifdef __GNUC__
#define _normal_inline static inline __attribute__((always_inline))
#define _hotbed_inline static inline __attribute__((always_inline, hot))
#define _coldbed_inline static inline __attribute__((always_inline, cold))
#define _noreturn_inline static inline __attribute__((noreturn, always_inline, hot))
#define _fn_metadata file __FILE__, line __LINE__
#define _fn_name __PRETTY_FUNCTION__
#elif _MSC_VER
#define _normal_inline static inline __forceinline
#define _hotbed_inline static inline __forceinline
#define _coldbed_inline static inline __forceinline
#define _noreturn_inline static inline __forceinline _Noreturn
#define _fn_metadata file __FILE__, line __LINE__
#define _fn_name __func__
#else
#define _normal_inline static inline
#define _hotbed_inline static inline
#define _coldbed_inline static inline
#define _fn_metadata file __FILE__, line __LINE__
#define _fn_name __func__

#endif

#define _static_func static
#define _static_obj static

#define _str_raw(...) #__VA_ARGS__
#define STR(...) _str_raw (__VA_ARGS__)
#define STR_LF(...) STR (__VA_ARGS__ \n)
#define STR_CRLF(...) STR (__VA_ARGS__ \r\n)

#endif