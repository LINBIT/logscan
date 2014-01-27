/*
   Author: Andreas Gruenbacher <agruen@linbit.com>

   Copyright (C) 2013, 2014 LINBIT HA-Solutions GmbH, http://www.linbit.com

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
	{"chdir",    required_argument, 0, 'd' },
	{"sync",     no_argument, 0, 5 },
	{"yes",      required_argument, 0, 'y' },
	{"no",       required_argument, 0, 'n' },
	{"filter",   required_argument, 0, 'f' },
	{"label",    required_argument, 0, 2 },
	{"timeout",  required_argument, 0, 't' },
	{"silent",   no_argument, 0, 's' },
	{"verbose",  no_argument, 0, 'v' },
	{"debug",    no_argument, 0, 3 },
	{"version",  no_argument, 0, 4 },
	{"help",     no_argument, 0, 'h' },
	{}
};

const char *progname;
bool opt_silent, opt_verbose, opt_debug;
bool with_timeout = true;
int inotify_fd = -1;
unsigned int active_logfiles;

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
"  " PACKAGE_NAME " [global options] { {logfile} [local options] } ...\n"
"  " PACKAGE_NAME " --sync filename ...\n"
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
"    Use the specified label instead of the file name.  Can only be used as a\n"
"    local option.\n"
"\n"
"  -t timeout, --timeout=timeout\n"
"    Only wait for the specified amount of time (in seconds) and fail if\n"
"    some of the expected patterns do not match before then.  The default is\n"
"    to wait forever; a value of 0 means not to wait.  If this option is not\n"
"    given, the value of the LOGSCAN_TIMEOUT environment variable is used\n"
"    instead.\n"
"\n"
"  -p filename\n"
"    Remember the positions of the last matches in a file and resume\n"
"    the next match from there.\n"
"\n"
"  --silent, --verbose\n"
"    Do not print any messages about unexpected patterns or timeouts\n"
"    (--silent), or also report when expected patterns are matched\n"
"    (--verbose).\n"
"\n"
"  --chdir directory\n"
"    Change into the specified directory and interpret all filenames relative\n"
"    to there.\n"
"\n"
"  --sync\n"
"    For each of the specified position tracking files, set the next match\n"
"    position of each logfile found to the maximum for that logfile.\n"
"\n"
"\n", fmt ? stdout : stderr);
	}
	exit(fmt ? 2 : 0);
}

struct posfile {
	struct list_head list;  /* posfiles */
	const char *name;
	struct list_head expr;
	struct list_head other_logfiles;  /* struct other_logfile */
	bool changed;
};

struct logfile {
	struct list_head list;  /* logfiles */
	const char *name;
	int fd;
	struct buffer buffer;
	unsigned int wd;  /* inotify watch descriptor */
	struct list_head expr;
	unsigned int active_exprs;

	unsigned int line;
	off_t offset;
};

struct expr {
	struct list_head logfile_list;  /* logfile.expr */
	struct list_head posfile_list;  /* posfile.expr */
	struct logfile *logfile;
	const char *label;
	struct posfile *posfile;
	unsigned int line;
	off_t offset;
	struct list_head filter;  /* struct pattern */
	struct list_head good;  /* struct pattern */
	struct list_head bad;  /* struct pattern */
	bool done;
};

struct other_logfile {
	struct list_head list;  /* posfile.other_logfiles */
	const char *name;
	unsigned int line;
	off_t offset;
};

struct pattern {
	struct list_head list;
	const char *regex;
	regex_t reg;
	bool matches;
};

LIST_HEAD(logfiles);
LIST_HEAD(posfiles);

static void new_pattern(const char *regex, struct list_head *list)
{
	struct pattern *pattern;
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
	pattern->matches = false;
	list_add_tail(&pattern->list, list);
}

static struct other_logfile *new_other_logfile(const char *name,
					       unsigned int line,
					       off_t offset)
{
	struct other_logfile *other_logfile;

	other_logfile = xalloc(sizeof(*other_logfile));
	other_logfile->name = name;
	other_logfile->line = line;
	other_logfile->offset = offset;
	return other_logfile;
}

static void read_posfile(struct posfile *posfile)
{
	unsigned int new_logfiles = 0;
	struct expr *expr;
	FILE *f;

	list_for_each_entry(expr, &posfile->expr, posfile_list)
		new_logfiles++;

	f = fopen(posfile->name, "r");
	if (!f) {
		if (errno == ENOENT)
			return;
		fatal("%s: %s: %s", progname, posfile->name, strerror(errno));
	}
	for(;;) {
		struct other_logfile *other_logfile;
		unsigned int line;
		unsigned long offset;
		char *name = NULL, *c;
		size_t size;
		int ret;

		ret = fscanf(f, "%u %lu ", &line, &offset);
		if (ret == EOF && feof(f))
			break;
		if (ret != 2 || getline(&name, &size, f) < 0)
			fatal("%s: %s: Parse error", progname, posfile->name);
		c = strrchr(name, '\n');
		if (c)
			*c = 0;
		if (!*name)
			fatal("%s: %s: Parse error", progname, posfile->name);

		list_for_each_entry(expr, &posfile->expr, posfile_list) {
			if (!strcmp(name, expr->logfile->name)) {
				expr->line = line;
				expr->offset = offset;
				new_logfiles--;
				goto next;
			}
		}
		other_logfile = new_other_logfile(name, line, offset);
		name = NULL;
		list_add_tail(&other_logfile->list, &posfile->other_logfiles);
	    next:
		free(name);
	}
	fclose(f);
	if (new_logfiles)
		posfile->changed = true;
}

static void read_posfiles(void)
{
	struct posfile *posfile;

	list_for_each_entry(posfile, &posfiles, list)
		read_posfile(posfile);
}

static void write_posfile(struct posfile *posfile)
{
	struct expr *expr;
	struct other_logfile *other_logfile;
	char *tmpfile;
	FILE *f;

	tmpfile = xalloc(strlen(posfile->name) + 2);
	sprintf(tmpfile, "%s~", posfile->name);
	f = fopen(tmpfile, "w");
	if (!f)
		fatal("%s: %s: %s",
		      progname, tmpfile, strerror(errno));
	list_for_each_entry(expr, &posfile->expr, posfile_list) {
		fprintf(f, "%u %lu %s\n",
			expr->line, expr->offset, expr->logfile->name);
	}
	list_for_each_entry(other_logfile, &posfile->other_logfiles, list)
		fprintf(f, "%u %lu %s\n",
			other_logfile->line, other_logfile->offset, other_logfile->name);
	if (fclose(f))
		fatal("%s: %s: %s", progname, tmpfile, strerror(errno));
	if (rename(tmpfile, posfile->name))
		fatal("%s: Renaming file %s to %s: %s",
		      progname, tmpfile, posfile->name, strerror(errno));
	free(tmpfile);
}

static void write_posfiles(void)
{
	struct posfile *posfile;

	list_for_each_entry(posfile, &posfiles, list)
		if (posfile->changed)
			write_posfile(posfile);
}

static void seek_logfiles(void)
{
	struct logfile *logfile;

	list_for_each_entry(logfile, &logfiles, list) {
		struct expr *expr;

		logfile->line = (unsigned int)-1;
		logfile->offset = (off_t)((unsigned long long)(off_t)-1 >> 1);
		list_for_each_entry(expr, &logfile->expr, logfile_list) {
			if (!expr->posfile) {
				logfile->line = 1;
				logfile->offset = 0;
				break;
			}
			if (logfile->offset > expr->offset) {
				logfile->line = expr->line;
				logfile->offset = expr->offset;
			}
		}
		if (logfile->offset) {
			if (opt_debug)
				printf("%s: seeking to line %u at offset %lu\n",
				       logfile->name,
				       logfile->line,
				       (unsigned long) logfile->offset);
			if (lseek(logfile->fd, logfile->offset, SEEK_SET) == (off_t) -1)
				fatal("%s: %s: failed to seek: %s",
				      progname, logfile->name, strerror(errno));
		}
	}
}

static bool all_matched(struct list_head *patterns)
{
	struct pattern *pattern;

	list_for_each_entry(pattern, patterns, list) {
		if (!pattern->matches)
			return false;
	}
	return true;
}

static bool any_matched(struct list_head *patterns)
{
	struct pattern *pattern;

	list_for_each_entry(pattern, patterns, list) {
		if (pattern->matches)
			return true;
	}
	return false;
}

static void scan_line(struct logfile *logfile, char *line, unsigned int length)
{
	struct expr *expr;

	line[length - 1] = 0;
	list_for_each_entry(expr, &logfile->expr, logfile_list) {
		struct pattern *pattern;

		if (expr->done || expr->offset > logfile->offset)
			continue;
		if (expr->offset != logfile->offset ||
		    expr->line != logfile->line) {
			fprintf(stderr, "%s: no line break at position %ld for"
					"tracking file %s; skipping %u "
					"characters\n",
				logfile->name,
				expr->offset,
				expr->posfile->name,
				(unsigned int)(logfile->offset - expr->offset));
			expr->line = logfile->line;
			expr->offset = logfile->offset;
			if (expr->posfile)
				expr->posfile->changed = true;
		}

		list_for_each_entry(pattern, &expr->filter, list) {
			if (regexec(&pattern->reg, line, 0, NULL, 0))
				goto next;
		}
		list_for_each_entry(pattern, &expr->good, list) {
			if (!regexec(&pattern->reg, line, 0, NULL, 0)) {
				pattern->matches = true;
				if (all_matched(&expr->good)) {
					expr->done = true;
					logfile->active_exprs--;
					if (!logfile->active_exprs)
						active_logfiles--;
				}
				if (opt_verbose)
					printf("Pattern '%s' matches at %s:%u\n",
					       pattern->regex, expr->label, expr->line);
			}
		}
		list_for_each_entry(pattern, &expr->bad, list) {
			if (!regexec(&pattern->reg, line, 0, NULL, 0)) {
				if (!opt_silent)
					fprintf(stderr, "Unexpected pattern '%s' "
							"matches at %s:%u\n",
					       pattern->regex, expr->label, expr->line);
				pattern->matches = true;
				expr->done = true;
				logfile->active_exprs--;
				if (!logfile->active_exprs)
					active_logfiles--;
			}
		}
	    next:
		expr->line++;
		expr->offset += length;
		if (expr->posfile)
			expr->posfile->changed = true;
	}
	line[length - 1] = '\n';
	logfile->line++;
	logfile->offset += length;
}

static char *get_next_line(struct buffer *buffer, unsigned int *length)
{
	char *start = buffer_read_pos(buffer);
	char *nl = memchr(start, '\n', buffer_size(buffer));
	if (nl) {
		*length = nl - start + 1;
		buffer_advance_read(buffer, *length);
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

static void scan_file(struct logfile *logfile)
{
	char *line;
	unsigned int length;

	while (logfile->active_exprs) {
		ssize_t size;

		line = get_next_line(&logfile->buffer, &length);
		if (line) {
			scan_line(logfile, line, length);
			continue;
		}
		shift_buffer(&logfile->buffer);
		if (!buffer_available(&logfile->buffer))
			grow_buffer(&logfile->buffer, 1 << 12);
		size = read(logfile->fd, buffer_write_pos(&logfile->buffer),
			    buffer_available(&logfile->buffer));
		if (size <= 0) {
			if (size == 0 || (size < 0 && errno == EAGAIN))
				break;
			if (errno != EINTR)
				fatal("%s: %s: %s",
				      progname, logfile->name, strerror(errno));
		} else
			buffer_advance_write(&logfile->buffer, size);
	}
}

static void listen_for_changes(struct logfile *logfile)
{
	int ret;

	ret = inotify_add_watch(inotify_fd, logfile->name, IN_MODIFY);
	if (ret < 0)
		fatal("%s: watching %s: %s",
		      progname, logfile->name, strerror(errno));
	logfile->wd = ret;
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
		struct logfile *logfile;
		ssize_t ret;

		ret = read(inotify_fd, &event, sizeof(event));
		if (ret == -1 && errno == EINTR)
			continue;
		if (ret > 0 && ret != sizeof(event)) {
			errno = EINVAL;
			ret = -1;
		}
		if (ret == sizeof(event)) {
			list_for_each_entry(logfile, &logfiles, list)
				if (event.wd == logfile->wd)
					return logfile;
		} else if (ret < 0 && errno != EAGAIN)
			fatal("%s: waiting for log entries: %s",
			      progname, strerror(errno));
		wait_for_event();
		if (got_interrupt_sig || got_alarm_sig)
			return NULL;
	}
}

static void scan(void)
{
	struct logfile *logfile;

	setvbuf(stdout, NULL, _IOLBF, BUFSIZ);
	setvbuf(stderr, NULL, _IOLBF, BUFSIZ);

	list_for_each_entry(logfile, &logfiles, list)
		scan_file(logfile);
	if (with_timeout && active_logfiles) {
		inotify_fd = inotify_init1(IN_NONBLOCK);
		if (inotify_fd < 0)
			fatal("%s: waiting for log entries: %s",
			      progname, strerror(errno));
		list_for_each_entry(logfile, &logfiles, list) {
			listen_for_changes(logfile);
			scan_file(logfile);
		}
		while (active_logfiles) {
			logfile = next_event();
			if (!logfile)
				break;
			scan_file(logfile);
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
	struct logfile *logfile;

	list_for_each_entry(logfile, &logfiles, list) {
		struct expr *expr;

		list_for_each_entry(expr, &logfile->expr, logfile_list) {
			struct pattern *pattern;
			bool printed = false;

			if (expr->done)
				continue;
			list_for_each_entry(pattern, &expr->good, list) {
				if (pattern->matches)
					continue;
				if (why) {
					fputs(why, stderr);
					why = NULL;
				}
				if (!printed) {
					fprintf(stderr, "%s: '%s'", expr->label, pattern->regex);
					printed = true;
				} else
					fprintf(stderr, ", '%s'", pattern->regex);
			}
			if (printed)
				fprintf(stderr, "\n");
		}
	}
}

static struct posfile *new_posfile(const char *name)
{
	struct posfile *posfile;

	list_for_each_entry(posfile, &posfiles, list) {
		if (!strcmp(posfile->name, name))
			return posfile;
	}

	posfile = xalloc(sizeof(*posfile));
	posfile->name = name;
	INIT_LIST_HEAD(&posfile->expr);
	INIT_LIST_HEAD(&posfile->other_logfiles);
	posfile->changed = false;
	list_add_tail(&posfile->list, &posfiles);
	return posfile;
}

static void append_patterns(struct list_head *to, struct list_head *from)
{
	struct pattern *pattern;

	list_for_each_entry(pattern, from, list) {
		struct pattern *copy;

		copy = xalloc(sizeof(*copy));
		*copy = *pattern;
		list_add_tail(&copy->list, to);
	}
}

static void append_to_expr(struct expr *to, struct expr *from)
{
	append_patterns(&to->filter, &from->filter);
	append_patterns(&to->good, &from->good);
	append_patterns(&to->bad, &from->bad);
}

static struct expr *new_expr(struct logfile *logfile, struct expr *global_expr)
{
	struct expr *expr;

	expr = xalloc(sizeof(*expr));
	INIT_LIST_HEAD(&expr->logfile_list);
	INIT_LIST_HEAD(&expr->posfile_list);
	expr->logfile = logfile;
	expr->label = logfile ? logfile->name : NULL;
	expr->posfile = NULL;
	expr->line = 1;
	expr->offset = 0;
	INIT_LIST_HEAD(&expr->filter);
	INIT_LIST_HEAD(&expr->good);
	INIT_LIST_HEAD(&expr->bad);
	if (global_expr)
		append_to_expr(expr, global_expr);
	expr->done = false;
	if (logfile)
		logfile->active_exprs++;
	return expr;
}

static struct logfile *new_logfile(const char *name)
{
	struct logfile *logfile;

	list_for_each_entry(logfile, &logfiles, list)
		if (!strcmp(logfile->name, name))
			return logfile;

	logfile = xalloc(sizeof(*logfile));
	logfile->name = name;
	init_buffer(&logfile->buffer, 1 << 12);
	INIT_LIST_HEAD(&logfile->expr);
	logfile->active_exprs = 0;
	logfile->line = 1;
	logfile->offset = 0;
	list_add_tail(&logfile->list, &logfiles);
	active_logfiles++;
	return logfile;
}

static void open_logfile(struct logfile *logfile)
{
	logfile->fd = open(logfile->name, O_RDONLY | O_NONBLOCK);
	if (logfile->fd < 0)
		fatal("%s: %s: %s",
		      progname, logfile->name, strerror(errno));
}

static struct expr *add_new_expr(struct logfile *logfile,
				 struct expr *global_expr)
{
	struct expr *expr;

	expr = new_expr(logfile, global_expr);
	list_add_tail(&expr->logfile_list, &logfile->expr);
	if (global_expr && global_expr->posfile) {
		expr->posfile = global_expr->posfile;
		list_add_tail(&expr->posfile_list, &expr->posfile->expr);
	}
	return expr;
}

static struct expr *find_posfile(struct posfile *posfile,
				 struct logfile *logfile)
{
	struct expr *expr;

	list_for_each_entry(expr, &logfile->expr, logfile_list)
		if (expr->posfile == posfile)
			return expr;
	return NULL;
}

static void splice_into_expr(struct expr *to, struct expr *from)
{
	list_splice_tail(&from->filter, &to->filter);
	list_splice_tail(&from->good, &to->good);
	list_splice_tail(&from->bad, &to->bad);
}

static void check_expr(struct expr *expr) {
	struct expr *first_expr;

	if (list_empty(&expr->good) && list_empty(&expr->bad))
		usage("%s: no search patterns specified", expr->logfile->name);
	if (!expr->posfile)
		return;
	first_expr = find_posfile(expr->posfile, expr->logfile);
	if (first_expr == expr)
		return;
	splice_into_expr(first_expr, expr);
	list_del(&expr->logfile_list);
	list_del(&expr->posfile_list);
	expr->logfile->active_exprs--;
	free(expr);
}

static void sync_new_posfile(const char *name)
{
	struct posfile *posfile;

	posfile = new_posfile(optarg);
	read_posfile(posfile);
	while (!list_empty(&posfile->other_logfiles)) {
		struct other_logfile *other_logfile;
		struct logfile *logfile;
		struct expr *expr;

		other_logfile = list_first_entry(&posfile->other_logfiles,
						 struct other_logfile, list);
		logfile = new_logfile(other_logfile->name);
		expr = add_new_expr(logfile, NULL);
		expr->posfile = posfile;
		list_add_tail(&expr->posfile_list, &posfile->expr);
		expr->line = other_logfile->line;
		expr->offset = other_logfile->offset;
		list_del(&other_logfile->list);
		free(other_logfile);
	}
}

static void sync_posfiles(void)
{
	struct logfile *logfile;

	list_for_each_entry(logfile, &logfiles, list) {
		struct expr *expr;

		list_for_each_entry(expr, &logfile->expr, logfile_list) {
			if (expr->offset > logfile->offset) {
				logfile->line = expr->line;
				logfile->offset = expr->offset;
			}
		}
	}

	list_for_each_entry(logfile, &logfiles, list) {
		struct expr *expr;

		list_for_each_entry(expr, &logfile->expr, logfile_list) {
			if (expr->offset != logfile->offset) {
				expr->line = logfile->line;
				expr->offset = logfile->offset;
				expr->posfile->changed = true;
			}
		}
	}
}

int main(int argc, char *argv[])
{
	const char *opt_t = NULL;
	struct expr *global_expr = new_expr(NULL, NULL), *expr = global_expr;
	struct logfile *logfile = NULL;
	bool opt_sync = false;

	progname = basename(argv[0]);

	for(;;) {
		int c;

		c = getopt_long(argc, argv, "-y:n:f:p:t:d:svh", long_options, NULL);
		if (c == -1)
			break;

		switch(c) {
		case 'y':
			new_pattern(optarg, &expr->good);
			break;
		case 'n':
			new_pattern(optarg, &expr->bad);
			break;
		case 'f':
			new_pattern(optarg, &expr->filter);
			break;
		case 't':
			opt_t = optarg;
			break;
		case 'p':
			if (global_expr->posfile || (logfile && expr->posfile))
				usage("multiple conflicting -p options");
			expr->posfile = new_posfile(optarg);
			if (logfile)
				list_add_tail(&expr->posfile_list, &expr->posfile->expr);
			break;
		case 's':
			opt_silent = true;
			break;
		case 'v':
			opt_verbose = true;
			break;
		case 1:
			if (opt_sync) {
				sync_new_posfile(optarg);
			} else {
				if (logfile)
					check_expr(expr);
				logfile = new_logfile(optarg);
				open_logfile(logfile);
				expr = add_new_expr(logfile, global_expr);
			}
			break;
		case 2:  /* --label */
			if (!logfile)
				usage("option --label must follow a log file name");
			if (expr->label != expr->logfile->name)
				usage("option --label used twice in the same context");
			expr->label = optarg;
			break;
		case 3:  /* --debug */
			opt_debug = true;
			break;
		case 4:  /* --version */
			printf("%s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
			exit(0);
			break;
		case 5:  /* --sync */
			opt_sync = true;
			break;
		case 'd':
			if (chdir(optarg)) {
				perror(optarg);
				exit(1);
			}
			break;
		case 'h':
			usage(NULL);
		case '?':
			exit(2);
		}
	}

	if (opt_sync) {
		sync_posfiles();
		write_posfiles();
		return 0;
	}

	if (list_empty(&logfiles))
		usage("command line arguments missing");
	check_expr(expr);

	if (!opt_t)
		opt_t = getenv("LOGSCAN_TIMEOUT");

	read_posfiles();
	seek_logfiles();
	set_signals();
	if (opt_t)
		set_timeout(opt_t);
	scan();
	write_posfiles();
	if (got_alarm_sig) {
		if (!opt_silent)
			print_missing_matches("Timeout waiting for patterns to match -- not matched:\n");
		return 1;
	} else if (got_interrupt_sig)
		return 1;
	else {
		bool good_okay = true, bad_okay = true;

		list_for_each_entry(logfile, &logfiles, list) {
			struct expr *expr;

			list_for_each_entry(expr, &logfile->expr, logfile_list) {
				good_okay = good_okay && all_matched(&expr->good);
				bad_okay = bad_okay && !any_matched(&expr->bad);
			}
		}

		if (!good_okay && !opt_silent)
			print_missing_matches("Patterns not matched:\n");
		return (good_okay && bad_okay) ? 0 : 1;
	}
}
