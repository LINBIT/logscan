/*
 * - Move the patterns into struct logfile, turn "matches" into "matched"
 * - copy the global patterns for each new logfile
 * - Find all occurrences of the same logfile; sort them by offset
 * - Start scanning for patterns from there
 */

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
"\n", fmt ? stdout : stderr);
	}
	exit(fmt ? 2 : 0);
}

struct posfile {
	struct list_head list;  /* posfiles */
	const char *name;
	struct list_head other_logfiles;  /* struct other_logfile */
};

struct expr {
	const char *label;
	struct posfile *posfile;
	unsigned int line;
	off_t offset;
	struct list_head filter;  /* struct pattern */
	struct list_head good;  /* struct pattern */
	struct list_head bad;  /* struct pattern */
	bool done;
};

struct logfile {
	struct list_head list;  /* logfiles */
	const char *name;
	int fd;
	struct buffer buffer;
	unsigned int wd;  /* inotify watch descriptor */
	struct expr *expr;
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
	FILE *f;

	f = fopen(posfile->name, "r");
	if (!f) {
		if (errno == ENOENT)
			return;
		fatal("%s: %s: %s", progname, posfile->name, strerror(errno));
	}
	for(;;) {
		struct logfile *logfile;
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

		list_for_each_entry(logfile, &logfiles, list) {
			if (logfile->expr->posfile == posfile &&
			    !strcmp(name, logfile->name)) {
				logfile->expr->line = line;
				logfile->expr->offset = offset;
				if (lseek(logfile->fd, offset, SEEK_SET) == (off_t) -1)
					fatal("%s: %s: failed to seek: %s",
					      progname, name, strerror(errno));
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
}

static void read_posfiles(void)
{
	struct posfile *posfile;

	list_for_each_entry(posfile, &posfiles, list)
		read_posfile(posfile);
}

static void write_posfile(struct posfile *posfile)
{
	struct logfile *logfile;
	struct other_logfile *other_logfile;
	char *tmpfile;
	FILE *f;

	tmpfile = xalloc(strlen(posfile->name) + 2);
	sprintf(tmpfile, "%s~", posfile->name);
	f = fopen(tmpfile, "w");
	if (!f)
		fatal("%s: %s: %s",
		      progname, tmpfile, strerror(errno));
	list_for_each_entry(logfile, &logfiles, list)
		if (logfile->expr->posfile == posfile)
			fprintf(f, "%u %lu %s\n",
				logfile->expr->line, logfile->expr->offset, logfile->name);
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
		write_posfile(posfile);
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

static void scan_line(struct logfile *logfile, char *line)
{
	char *nl = strchr(line, '\n');
	struct pattern *pattern;

	*nl = 0;
	list_for_each_entry(pattern, &logfile->expr->filter, list) {
		if (regexec(&pattern->reg, line, 0, NULL, 0))
			goto out;
	}
	list_for_each_entry(pattern, &logfile->expr->good, list) {
		if (!regexec(&pattern->reg, line, 0, NULL, 0)) {
			pattern->matches = true;
			if (all_matched(&logfile->expr->good)) {
				logfile->expr->done = true;
				active_logfiles--;
			}
			if (opt_verbose)
				printf("Pattern '%s' matches at %s:%u\n",
				       pattern->regex, logfile->expr->label, logfile->expr->line + 1);
		}
	}
	list_for_each_entry(pattern, &logfile->expr->bad, list) {
		if (!regexec(&pattern->reg, line, 0, NULL, 0)) {
			if (!opt_silent)
				fprintf(stderr, "Unexpected pattern '%s' "
						"matches at %s:%u\n",
				       pattern->regex, logfile->expr->label, logfile->expr->line + 1);
			pattern->matches = true;
			logfile->expr->done = true;
			active_logfiles--;
		}
	}

    out:
	*nl = '\n';

	logfile->expr->line++;
	logfile->expr->offset += nl - line + 1;
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

static void scan_file(struct logfile *logfile)
{
	char *line;

	while (!logfile->expr->done) {
		ssize_t size;

		line = get_next_line(&logfile->buffer);
		if (line) {
			scan_line(logfile, line);
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
		struct pattern *pattern;
		bool printed = false;

		if (logfile->expr->done)
			continue;
		list_for_each_entry(pattern, &logfile->expr->good, list) {
			if (pattern->matches)
				continue;
			if (why) {
				fputs(why, stderr);
				why = NULL;
			}
			if (!printed) {
				fprintf(stderr, "%s: '%s'", logfile->expr->label, pattern->regex);
				printed = true;
			} else
				fprintf(stderr, ", '%s'", pattern->regex);
		}
		if (printed)
			fprintf(stderr, "\n");
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
	INIT_LIST_HEAD(&posfile->other_logfiles);
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

static struct expr *new_expr(const char *name, struct expr *expr)
{
	struct expr *new;

	new = xalloc(sizeof(*new));
	new->label = name;
	new->posfile = NULL;
	new->line = 0;
	new->offset = 0;
	INIT_LIST_HEAD(&new->filter);
	INIT_LIST_HEAD(&new->good);
	INIT_LIST_HEAD(&new->bad);
	if (expr) {
		append_patterns(&new->filter, &expr->filter);
		append_patterns(&new->good, &expr->good);
		append_patterns(&new->bad, &expr->bad);
	}
	new->done = false;
	return new;
}

static struct logfile *new_logfile(const char *name, struct expr *expr)
{
	struct logfile *logfile;

	logfile = xalloc(sizeof(*logfile));
	logfile->name = name;
	logfile->fd = open(logfile->name, O_RDONLY | O_NONBLOCK);
	if (logfile->fd < 0)
		fatal("%s: %s: %s",
		      progname, logfile->name, strerror(errno));
	init_buffer(&logfile->buffer, 1 << 12);
	logfile->expr = new_expr(name, expr);
	list_add_tail(&logfile->list, &logfiles);
	return logfile;
}

int main(int argc, char *argv[])
{
	const char *opt_p = NULL, *opt_t = NULL;
	struct expr *global_expr = new_expr(NULL, NULL), *expr = global_expr;
	struct logfile *last_logfile = NULL;
	struct logfile *logfile;

	progname = basename(argv[0]);

	for(;;) {
		int c;

		c = getopt_long(argc, argv, "-y:n:f:p:t:svh", long_options, NULL);
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
			if (!last_logfile)
				opt_p = optarg;
			else
				last_logfile->expr->posfile = new_posfile(optarg);
			break;
		case 's':
			opt_silent = true;
			break;
		case 'v':
			opt_verbose = true;
			break;
		case 1:
			last_logfile = new_logfile(optarg, global_expr);
			expr = last_logfile->expr;
			break;
		case 2:  /* --label */
			if (!last_logfile)
				usage("option --label must follow a log file name");
			last_logfile->expr->label = optarg;
			break;
		case 3:  /* --version */
			printf("%s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
			exit(0);
		case 'h':
			usage(NULL);
		case '?':
			exit(2);
		}
	}
	if (list_empty(&logfiles))
		usage("command line arguments missing");
	list_for_each_entry(logfile, &logfiles, list) {
		if (list_empty(&logfile->expr->good) &&
		    list_empty(&logfile->expr->bad))
			usage("%s: no search patterns specified", logfile->name);
		active_logfiles++;
	}
	if (!opt_t)
		opt_t = getenv("LOGSCAN_TIMEOUT");

	if (opt_p) {
		list_for_each_entry(logfile, &logfiles, list)
			if (!logfile->expr->posfile)
				logfile->expr->posfile = new_posfile(opt_p);
	}

	read_posfiles();
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
			good_okay = good_okay && all_matched(&logfile->expr->good);
			bad_okay = bad_okay && !any_matched(&logfile->expr->bad);
		}

		if (!good_okay && !opt_silent)
			print_missing_matches("Patterns not matched:\n");
		return (good_okay && bad_okay) ? 0 : 1;
	}
}
