/* Copyright (c) 2023 Cameron Harper
 *
 * */

#ifndef LOG_H
#define LOG_H

#include <stdio.h>

extern bool log_enabled;

#define LOG(...) do{if(log_enabled){printf(__VA_ARGS__);printf("\n");fflush(stdout);}}while(0);
#define ERROR(...) do{fprintf(stderr, "%s: ", __FILE__);fprintf(stderr, "error: ");fprintf(stderr, __VA_ARGS__);fprintf(stderr, "\n");fflush(stderr);}while(0);

#endif
