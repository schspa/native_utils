/*
 * main.c --- main.c
 *
 * Copyright (C) 2019, , all rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <dirent.h>

#include "inc/inject.h"

int find_pid_of(const char* process_name){
    int id;
    pid_t pid = -1;
    DIR* dir;
    FILE* fp;
    char filename[32];
    char cmdline[296];

    struct dirent* entry;

    if(process_name == NULL){
        return -1;
    }

    dir = opendir("/proc");
    if(dir == NULL){
        return -1;
    }

    while((entry = readdir(dir)) != NULL){
        id = atoi(entry->d_name);
        if(id != 0){
            sprintf(filename, "/proc/%d/cmdline", id);
            fp = fopen(filename, "r");
            if(fp){
                fgets(cmdline, sizeof(cmdline), fp);
                fclose(fp);// 释放对目标进程的附加调试

                if(strcmp(process_name, cmdline) == 0){
                    pid = id;
                    break;
                }
            }
        }
    }
    closedir(dir);
    return pid;
}

static void print_help(char *processname) {
	printf("Usage: %s [option]\n"
		   "\t-p/--pid <pid>\n"
		   "\t-n/--name process_name\n"
		   "\t-l/--library libsample.so\n", processname);
}

int main(int argc, char *argv[]) {
	int pid = 0;
	char *library;
	char *entry = NULL, *argument = NULL;
    const char *optstring = "p:n:l:e:a:";
    int c;
    int f_l = 0, opt_index = -1;
    struct option opts[] = {
        {"pid", 1, NULL, 'p'},
        {"name", 1, NULL, 'n'},
        {"library", 1, NULL, 'l'},
		{"entry", 1, NULL, 'e'},
		{"arg", 1, NULL, 'a'},
		{0, 0, 0, 0}
    };

    while((c = getopt_long_only(argc, argv, optstring, opts, &opt_index)) != -1) {
        switch(c) {
		case 'n':
			pid = find_pid_of(optarg);
			break;
		case 'p':
			pid = atoi(optarg);
			break;
		case 'l':
			f_l = 1;
			library = optarg;
			break;
		case 'e':
			entry = optarg;
			break;
		case 'a':
			argument = optarg;
			break;
		default:
			break;
        }
    }

	if (!f_l || pid <= 0) {
		print_help(argv[0]);
		return 0;
	}

	inject_remote_process(pid, library, entry, argument, argument ? strlen(argument) + 1 : 0);
	return 0;

}
