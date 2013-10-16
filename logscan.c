/*
   Author: Andreas Gruenbacher <agruen@linbit.com>

   Copyright (C) 2013 LINBIT HA-Solutions GmbH, http://www.linbit.com

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   See the COPYING file for details.
*/

#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <sys/time.h>
#include <math.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <regex.h>

#include "list.h"
#include "buffer.h"
#include "error.h"

static struct option long_options[] = {
	{"yes",      required_argument, 0, 'y' },
	{"no",       required_argument, 0, 'n' },
	{"filter",   required_argument, 0, 'f' },
	{"label",    required_argument, 0, 2 },
	{"timeout",  required_argument, 0, 't' },
	{"silent",   no_argument, 0, 's' },
	{"verbose",  no_argument, 0, 'v' },
	{"version",  no_argument, 0, 3 },
	{"help",     no_argument, 0, 'h' },
	{}
};

const char *progname;
bool opt_silent, opt_verbose;
bool with_timeout = true;
int inotify_fd = -1;

static void usage(const char *fmt, ...)
{
	if (fmt) {
		va_list ap;

		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		fputs("\nTry " PACKAGE_NAME " -h.\n", stderr);
		va_end(ap);
	} else {
		fputs(
PACKAGE_NAME " - Scan for patterns in log files\n"
"\n"
"Watch one or more logfiles and check for regular expression patterns.\n"
"This utility reports which patterns match where, and terminates when all\n"
"positive matches (-y) or a negative match (-n) was found in each logfile.\n"
"\n"
"USAGE\n"
"  " PACKAGE_NAME " [options] {filename} ...\n"
"\n"
"OPTIONS\n"
"  -y pattern, --yes=pattern\n"
"    Match this regular expression pattern.  This option can be used\n"
"    multiple times; all of the patterns must match in arbitrary order.\n"
"\n"
"  -n pattern, --no=pattern\n"
"    Do not allow this regular expression pattern to match.  This\n"
"    option can be used multiple times; none of the patterns must\n"
"    match.\n"
"\n"
"  -f pattern, --filter=pattern\n"
"    Only look at lines matching this regular expression pattern.\n"
"\n"
"  --label label\n"
"    Use the specified label instead of the filename for the next logfile.\n"
"\n"
"  -t timeout, --timeout=timeout\n"
"    Only wait for the specified amount of time and fail if some of the\n"
"    expected patterns do not match before then.  The default is to wait\n"
"    forever; a value of 0 means not to wait.  If this option is not given,\n"
"    the value of the LOGSCAN_TIMEOUT environment variable is used instead.\n"
"\n"
"  -p filename\n"
"    Remember the positions of the last matches in a file and resume\n"
"    the next match from there.\n"
"\n"
"  --silent, --verbose\n"
"    Do not print any messages about unexpected patterns or timeouts\n"
"    (--silent), or also report when expected patterns are matched\n"
"    (--verbose).\n"
"\n", fmt ? stdout : stderr);
	}
	exit(fmt ? 2 : 0);
}

struct logfile {
	struct list_head list;
	const char *label;
	const char *name;
	int fd;
	unsigned int line;
	off_t offset;
	struct buffer buffer;
	unsigned int index;
	unsigned int wd;  /* inotify watch descriptor */
	bool done;
};

struct event_pattern {
	struct list_head list;
	const char *regex;
	regex_t reg;
	unsigned int *matches;
};

LIST_HEAD(files);
LIST_HEAD(other_files);
LIST_HEAD(good_patterns);
LIST_HEAD(bad_patterns);
LIST_HEAD(filter_patterns);

static void new_pattern(const char *regex, struct list_head *list)
{
	struct event_pattern *pattern;
	int ret;

	pattern = xalloc(sizeof(*pattern));
	pattern->regex = regex;
	ret = regcomp(&pattern->reg, regex, REG_EXTENDED | REG_NOSUB);
	if (ret) {
		size_t size = regerror(ret, &pattern->reg, NULL, 0);
		char *error = xalloc(size);
		regerror(ret, &pattern->reg, error, size);
		usage("Pattern '%s': %s", regex, error);
	}
	pattern->matches = NULL;
	list_add_tail(&pattern->list, list);
}

static void read_positions(const char *dumpfile)
{
	FILE *f;

	f = fopen(dumpfile, "r");
	if (!f) {
		if (errno == ENOENT)
			return;
		fatal("%s: %s: %s", progname, dumpfile, strerror(errno));
	}
	for(;;) {
		struct logfile *file;
		unsigned int line;
		unsigned long offset;
		char *name = NULL, *c;
		size_t size;
		int ret;

		ret = fscanf(f, "%u %lu ", &line, &offset);
		if (ret == EOF && feof(f))
			break;
		if (ret != 2 || getline(&name, &size, f) < 0)
			fatal("%s: %s: Parse error", progname, dumpfile);
		c = strrchr(name, '\n');
		if (c)
			*c = 0;
		if (!*name)
			fatal("%s: %s: Parse error", progname, dumpfile);

		list_for_each_entry(file, &files, list) {
			if (!strcmp(name, file->name)) {
				file->line = line;
				file->offset = offset;
				if (lseek(file->fd, offset, SEEK_SET) == (off_t) -1)
					fatal("%s: %s: failed to seek: %s",
					      progname, name, strerror(errno));
				goto next;
			}
		}
		file = xalloc(sizeof(*file));
		file->name = name;
		name = NULL;
		file->line = line;
		file->offset = offset;
		list_add_tail(&file->list, &other_files);
	    next:
		free(name);
	}
	fclose(f);
}

static void write_positions(const char *dumpfile)
{
	struct logfile *file;
	char *tmpfile;
	FILE *f;

	tmpfile = xalloc(strlen(dumpfile) + 2);
	sprintf(tmpfile, "%s~", dumpfile);
	f = fopen(tmpfile, "w");
	if (!f)
		fatal("%s: %s: %s",
		      progname, tmpfile, strerror(errno));
	list_for_each_entry(file, &files, list)
		fprintf(f, "%u %lu %s\n",
			file->line, file->offset, file->name);
	list_for_each_entry(file, &other_files, list)
		fprintf(f, "%u %lu %s\n",
			file->line, file->offset, file->name);
	if (fclose(f))
		fatal("%s: %s: %s", progname, tmpfile, strerror(errno));
	if (rename(tmpfile, dumpfile))
		fatal("%s: Renaming file %s to %s: %s",
		      progname, tmpfile, dumpfile, strerror(errno));
	free(tmpfile);
}

static void allocate_matches(struct event_pattern *pattern,
			     unsigned int number_of_files)
{
	size_t size = number_of_files * sizeof(*pattern->matches);

	pattern->matches = xalloc(size);
	memset(pattern->matches, 0, size);
}

static bool all_matched_for_file(struct list_head *patterns, int index)
{
	struct event_pattern *pattern;

	list_for_each_entry(pattern, patterns, list) {
		if (!pattern->matches[index])
			return false;
	}
	return true;
}

static bool all_matched(struct list_head *patterns, int number_of_files)
{
	struct event_pattern *pattern;

	list_for_each_entry(pattern, patterns, list) {
		int index;

		for (index = 0; index < number_of_files; index++)
			if (!pattern->matches[index])
				return false;
	}
	return true;
}

static bool any_matched(struct list_head *patterns, int number_of_files)
{
	struct event_pattern *pattern;

	list_for_each_entry(pattern, patterns, list) {
		int index;

		for (index = 0; index < number_of_files; index++)
			if (pattern->matches[index])
				return true;
	}
	return false;
}

static void scan_line(struct logfile *file, char *line)
{
	char *nl = strchr(line, '\n');
	struct event_pattern *pattern;

	*nl = 0;
	list_for_each_entry(pattern, &filter_patterns, list) {
		if (regexec(&pattern->reg, line, 0, NULL, 0))
			goto out;
	}
	list_for_each_entry(pattern, &good_patterns, list) {
		if (!regexec(&pattern->reg, line, 0, NULL, 0)) {
			pattern->matches[file->index]++;
			file->done = all_matched_for_file(&good_patterns, file->index);
			if (opt_verbose)
				printf("Pattern '%s' matches at %s:%u\n",
				       pattern->regex, file->label, file->line + 1);
		}
	}
	list_for_each_entry(pattern, &bad_patterns, list) {
		if (!regexec(&pattern->reg, line, 0, NULL, 0)) {
			if (!opt_silent)
				fprintf(stderr, "Unexpected pattern '%s' "
						"matches at %s:%u\n",
				       pattern->regex, file->label, file->line + 1);
			pattern->matches[file->index]++;
			file->done = true;
		}
	}

    out:
	*nl = '\n';

	file->line++;
	file->offset += nl - line + 1;
}

char *get_next_line(struct buffer *buffer)
{
	char *start = buffer_read_pos(buffer);
	char *nl = memchr(start, '\n', buffer_size(buffer));
	if (nl) {
		buffer_advance_read(buffer, nl - start + 1);
		return start;
	}
	return NULL;
}

static void shift_buffer(struct buffer *buffer)
{
	memmove(buffer->buffer, buffer_read_pos(buffer), buffer_size(buffer));
	buffer->end -= buffer->start;
	buffer->start = 0;
}

static void scan_file(struct logfile *file)
{
	char *line;

	while (!file->done) {
		ssize_t size;

		line = get_next_line(&file->buffer);
		if (line) {
			scan_line(file, line);
			continue;
		}
		shift_buffer(&file->buffer);
		if (!buffer_available(&file->buffer))
			grow_buffer(&file->buffer, 1 << 12);
		size = read(file->fd, buffer_write_pos(&file->buffer),
			    buffer_available(&file->buffer));
		if (size <= 0) {
			if (size == 0 || (size < 0 && errno == EAGAIN))
				break;
			if (errno != EINTR)
				fatal("%s: %s: %s",
				      progname, file->name, strerror(errno));
		} else
			buffer_advance_write(&file->buffer, size);
	}
}

static void listen_for_changes(struct logfile *file)
{
	int ret;

	ret = inotify_add_watch(inotify_fd, file->name, IN_MODIFY);
	if (ret < 0)
		fatal("%s: watching %s: %s",
		      progname, file->name, strerror(errno));
	file->wd = ret;
}

static volatile sig_atomic_t got_interrupt_sig;
static volatile sig_atomic_t got_alarm_sig;

static void interrupt_sig_handler(int sig)
{
	got_interrupt_sig = 1;
}

static void alarm_sig_handler(int sig)
{
	got_alarm_sig = 1;
}

static void set_signals(void)
{
	sigset_t sigmask;
	struct sigaction sa;

	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGINT);
	sigaddset(&sigmask, SIGALRM);
	if (sigprocmask(SIG_BLOCK, &sigmask, NULL))
		fatal("blocking SIGINT and SIGALRM signals");

        sa.sa_flags = 0;
        sigemptyset(&sa.sa_mask);
        sa.sa_handler = interrupt_sig_handler;
        if (sigaction(SIGINT, &sa, NULL))
                fatal("setting SIGINT signal");
        sa.sa_handler = alarm_sig_handler;
        if (sigaction(SIGALRM, &sa, NULL))
                fatal("setting SIGALRM signal");
}

void wait_for_event(void)
{
	fd_set rfds;
	int ret;

	FD_ZERO(&rfds);
	FD_SET(inotify_fd, &rfds);
	for(;;) {
		sigset_t empty_mask;

		sigemptyset(&empty_mask);
		ret = pselect(inotify_fd + 1, &rfds, NULL, NULL, NULL, &empty_mask);
		if (ret < 0) {
			if (errno != EINTR)
				fatal("%s: waiting for log entries", progname);
			if (got_interrupt_sig || got_alarm_sig)
				break;
		} else if (ret == 1)
			break;
	}
}

struct logfile *next_event(void)
{
	for(;;) {
		struct inotify_event event;
		struct logfile *file;
		ssize_t ret;

		ret = read(inotify_fd, &event, sizeof(event));
		if (ret == -1 && errno == EINTR)
			continue;
		if (ret > 0 && ret != sizeof(event)) {
			errno = EINVAL;
			ret = -1;
		}
		if (ret == sizeof(event)) {
			list_for_each_entry(file, &files, list)
				if (event.wd == file->wd)
					return file;
		} else if (ret < 0 && errno != EAGAIN)
			fatal("%s: waiting for log entries: %s",
			      progname, strerror(errno));
		wait_for_event();
		if (got_interrupt_sig || got_alarm_sig)
			return NULL;
	}
}

static bool all_done(void)
{
	struct logfile *file;

	list_for_each_entry(file, &files, list)
		if (!file->done)
			return false;
	return true;
}

static void scan(void)
{
	struct logfile *file;

	list_for_each_entry(file, &files, list)
		scan_file(file);
	if (with_timeout && !all_done()) {
		inotify_fd = inotify_init1(IN_NONBLOCK);
		if (inotify_fd < 0)
			fatal("%s: waiting for log entries: %s",
			      progname, strerror(errno));
		list_for_each_entry(file, &files, list) {
			listen_for_changes(file);
			scan_file(file);
		}
		while (!all_done()) {
			file = next_event();
			if (!file)
				break;
			scan_file(file);
		}
	}
}

static void set_timeout(const char *arg)
{
	struct itimerval value = { };
	double t, frac;
	char *end;
	int ret;

	t = strtod(arg, &end);
	if (*end || t < 0)
		usage("timeout %s: %s", arg, strerror(EINVAL));
	frac = modf(t, &t);
	value.it_value.tv_sec = floor(t);
	value.it_value.tv_usec = floor(frac * 1e6);
	if (value.it_value.tv_sec == 0 && value.it_value.tv_usec == 0)
		with_timeout = false;
	else {
		ret = setitimer(ITIMER_REAL, &value, NULL);
		if (ret != 0)
			fatal("setting timer");
	}
}

static void print_missing_matches(const char *why)
{
	struct logfile *file;

	list_for_each_entry(file, &files, list) {
		struct event_pattern *pattern;
		bool printed = false;

		if (file->done)
			continue;
		list_for_each_entry(pattern, &good_patterns, list) {
			if (pattern->matches[file->index])
				continue;
			if (why) {
				fputs(why, stderr);
				why = NULL;
			}
			if (!printed) {
				fprintf(stderr, "%s: '%s'", file->label, pattern->regex);
				printed = true;
			} else
				fprintf(stderr, ", '%s'", pattern->regex);
		}
		if (printed)
			fprintf(stderr, "\n");
	}
}

void logfile_arg(const char *name, const char *label, unsigned int index) {
	struct logfile *file;

	file = xalloc(sizeof(*file));
	file->label = label ? label : name;
	file->name = name;
	file->fd = open(file->name, O_RDONLY | O_NONBLOCK);
	if (file->fd < 0)
		fatal("%s: %s: %s",
		      progname, file->name, strerror(errno));
	file->offset = 0;
	init_buffer(&file->buffer, 1 << 12);
	file->index = index;
	file->done = false;
	list_add_tail(&file->list, &files);
}

int main(int argc, char *argv[])
{
	const char *opt_p = NULL, *opt_t = NULL, *opt_label = NULL;
	unsigned int number_of_files = 0;
	struct event_pattern *pattern;

	progname = basename(argv[0]);

	for(;;) {
		int c;

		c = getopt_long(argc, argv, "-y:n:f:p:t:svh", long_options, NULL);
		if (c == -1)
			break;

		switch(c) {
		case 'y':
			new_pattern(optarg, &good_patterns);
			break;
		case 'n':
			new_pattern(optarg, &bad_patterns);
			break;
		case 'f':
			new_pattern(optarg, &filter_patterns);
			break;
		case 't':
			opt_t = optarg;
			break;
		case 'p':
			opt_p = optarg;
			break;
		case 's':
			opt_silent = true;
			break;
		case 'v':
			opt_verbose = true;
			break;
		case 1:
			logfile_arg(optarg, opt_label, number_of_files++);
			opt_label = NULL;
			break;
		case 2:
			opt_label = optarg;
			break;
		case 3:
			printf("%s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
			exit(0);
		case 'h':
			usage(NULL);
		case '?':
			exit(2);
		}
	}
	if (list_empty(&files))
		usage("command line arguments missing");
	if (list_empty(&good_patterns) && list_empty(&bad_patterns))
		usage("no search patterns specified");
	if (!opt_t)
		opt_t = getenv("LOGSCAN_TIMEOUT");

	list_for_each_entry(pattern, &good_patterns, list)
		allocate_matches(pattern, number_of_files);
	list_for_each_entry(pattern, &bad_patterns, list)
		allocate_matches(pattern, number_of_files);

	if (opt_p)
		read_positions(opt_p);
	set_signals();
	if (opt_t)
		set_timeout(opt_t);
	scan();
	if (opt_p)
		write_positions(opt_p);
	if (got_alarm_sig) {
		if (!opt_silent)
			print_missing_matches("Timeout waiting for patterns to match -- not matched:\n");
		return 1;
	} else if (got_interrupt_sig)
		return 1;
	else {
		bool good_okay = all_matched(&good_patterns, number_of_files);
		bool bad_okay = !any_matched(&bad_patterns, number_of_files);

		if (!good_okay && !opt_silent)
			print_missing_matches("Patterns not matched:\n");
		return (good_okay && bad_okay) ? 0 : 1;
	}
}
