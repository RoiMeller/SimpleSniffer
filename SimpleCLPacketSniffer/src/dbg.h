/* The usual defense against accidentally including the file twice */
#ifndef __dbg_h__
#define __dbg_h__

/* Includes for the functions that these macros need */
#include <stdio.h>
#include <errno.h>
#include <string.h>

/* 
 ==============================================================================================
 The start of a #ifdef which lets you recompile your program so that all 
 the debug log messages are removed
 ==============================================================================================
*/
#ifdef NDEBUG

/*
 ==============================================================================================
 If you compile with NDEBUG defined, then "no debug" messages will remain. 
 You can see in this case the #define debug() is just replaced with nothing 
 (the right side is empty).
 ==============================================================================================
*/
#define debug(M, ...)

#else // The matching #else for the above #ifdef.

/*
 ==============================================================================================
 The alternative #define debug that translates any use of debug ("format", arg1, arg2) 
 into an fprintf call to stderr. The magic here is the use of ##__VA_ARGS__ which says 
 "put whatever they had for extra arguments (...) here". Also notice the use of 
 __FILE__ and __LINE__ to get the current file:line for the debug message.
 ==============================================================================================
*/
#define debug(M, ...) fprintf(stderr, "DEBUG %s:%d: " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)

#endif // The end of the #ifdef

/*
 ============================================================================================== 
 The clean_errno macro that's used in the others to get a safe readable version of errno.
 ============================================================================================== 
*/
#define clean_errno() (errno == 0 ? "None" : strerror(errno))

/*
 ==============================================================================================
 The log_err, log_warn, and log_info, macros for logging messages meant for the end user. 
 Works like debug but can't be compiled out.
 ----------------------------------------------------------------------------------------------
 The first macro, log_err is simpler and simply replace itself with a call to fprintf to stderr. 
 The only tricky part of this macro is the use of ... in the definition log_err(M, ...). 
 What this does is let you pass variable arguments to the macro, 
 so you can pass in the arguments that should go to fprintf. 
 How do they get injected into the fprintf call? Look at the end to the ##__VA_ARGS__ 
 and that's telling the CPP to take the args entered where the ... is, 
 and inject them at that part of the fprintf call.
 ==============================================================================================
*/
#define log_err(M, ...) fprintf(stderr, "[ERROR] (%s:%d: errno: %s) " M "\n", __FILE__, __LINE__, clean_errno(), ##__VA_ARGS__)
#define log_warn(M, ...) fprintf(stderr, "[WARN] (%s:%d: errno: %s) " M "\n", __FILE__, __LINE__, clean_errno(), ##__VA_ARGS__)
#define log_info(M, ...) fprintf(stderr, "[INFO] (%s:%d) " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)

/*
 ==============================================================================================
 The best macro ever, check will make sure the condition A is true, and if not logs the error M 
 (with variable arguments for log_err), then jumps to the function's error: for cleanup.
 ==============================================================================================
*/
#define check(A, M, ...) if(!(A)) { log_err(M, ##__VA_ARGS__); errno=0; goto error; }

/*
 ==============================================================================================
 The 2nd best macro ever, sentinel is placed in any part of a function that shouldn't run, 
 and if it does prints an error message then jumps to the error: label. 
 You put this in if-statements and switch-statements to catch conditions that shouldn't happen, 
 like the default:.
 ==============================================================================================
*/
#define sentinel(M, ...)  { log_err(M, ##__VA_ARGS__); errno=0; goto error; }

/*
 ==============================================================================================
 A short-hand macro check_mem that makes sure a pointer is valid, 
 and if it isn't reports it as an error with "Out of memory."
 ==============================================================================================
*/
#define check_mem(A) check((A), "Out of memory.")

/*
 ==============================================================================================
 An alternative macro check_debug that still checks and handles an error, 
 but if the error is common then you don't want to bother reporting it. 
 In this one it will use debug instead of log_err to report the message, 
 so when you define NDEBUG the check still happens, the error jump goes off, 
 but the message isn't printed.
 ============================================================================================== 
*/
#define check_debug(A, M, ...) if(!(A)) { debug(M, ##__VA_ARGS__); errno=0; goto error; }

#endif

