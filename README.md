# Stackls: List the Application Stack
### For GNU Linux and Micrsoft Windows (Using Win32 API)


### How to Build:

Use `cmake(1)` to generate the build files both on Linux and Windows, as you desire. Macros have been provided to make the Windows version work on both GCC-based compilers, and MSVC.


### How to Use:

The signature is:

```
stackls [-o output-file] PROCID
```

On Linux, `PROCID` is the value you get from `ps(1)`. On Windows, it's the string you get from Task Manager for example `cmd.exe`.