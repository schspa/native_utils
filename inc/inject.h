#ifndef INJECT_H
#define INJECT_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/user.h>

int inject_remote_process(pid_t target_pid, const char* library_path, const char* function_name, const char* param, size_t param_size);

#endif
