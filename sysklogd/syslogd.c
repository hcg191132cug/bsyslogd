/* vi: set sw=4 ts=4: */
/*
 * Mini syslogd implementation for busybox
 *
 * Copyright (C) 1999-2004 by Erik Andersen <andersen@codepoet.org>
 *
 * Copyright (C) 2000 by Karl M. Hegbloom <karlheg@debian.org>
 *
 * "circular buffer" Copyright (C) 2001 by Gennady Feldman <gfeldman@gena01.com>
 *
 * Maintainer: Gennady Feldman <gfeldman@gena01.com> as of Mar 12, 2001
 *
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 */
//config:config SYSLOGD
//config:	bool "syslogd"
//config:	default y
//config:	help
//config:	  The syslogd utility is used to record logs of all the
//config:	  significant events that occur on a system. Every
//config:	  message that is logged records the date and time of the
//config:	  event, and will generally also record the name of the
//config:	  application that generated the message. When used in
//config:	  conjunction with klogd, messages from the Linux kernel
//config:	  can also be recorded. This is terribly useful,
//config:	  especially for finding what happened when something goes
//config:	  wrong. And something almost always will go wrong if
//config:	  you wait long enough....
//config:
//config:config FEATURE_ROTATE_LOGFILE
//config:	bool "Rotate message files"
//config:	default y
//config:	depends on SYSLOGD
//config:	help
//config:	  This enables syslogd to rotate the message files
//config:	  on his own. No need to use an external rotate script.
//config:
//config:config FEATURE_REMOTE_LOG
//config:	bool "Remote Log support"
//config:	default y
//config:	depends on SYSLOGD
//config:	help
//config:	  When you enable this feature, the syslogd utility can
//config:	  be used to send system log messages to another system
//config:	  connected via a network. This allows the remote
//config:	  machine to log all the system messages, which can be
//config:	  terribly useful for reducing the number of serial
//config:	  cables you use. It can also be a very good security
//config:	  measure to prevent system logs from being tampered with
//config:	  by an intruder.
//config:
//config:config FEATURE_SYSLOGD_DUP
//config:	bool "Support -D (drop dups) option"
//config:	default y
//config:	depends on SYSLOGD
//config:	help
//config:	  Option -D instructs syslogd to drop consecutive messages
//config:	  which are totally the same.
//config:
//config:config FEATURE_SYSLOGD_CFG
//config:	bool "Support syslog.conf"
//config:	default y
//config:	depends on SYSLOGD
//config:	help
//config:	  Supports restricted syslogd config. See docs/syslog.conf.txt
//config:
//config:config FEATURE_SYSLOGD_READ_BUFFER_SIZE
//config:	int "Read buffer size in bytes"
//config:	default 256
//config:	range 256 20000
//config:	depends on SYSLOGD
//config:	help
//config:	  This option sets the size of the syslog read buffer.
//config:	  Actual memory usage increases around five times the
//config:	  change done here.
//config:
//config:config FEATURE_IPC_SYSLOG
//config:	bool "Circular Buffer support"
//config:	default y
//config:	depends on SYSLOGD
//config:	help
//config:	  When you enable this feature, the syslogd utility will
//config:	  use a circular buffer to record system log messages.
//config:	  When the buffer is filled it will continue to overwrite
//config:	  the oldest messages. This can be very useful for
//config:	  systems with little or no permanent storage, since
//config:	  otherwise system logs can eventually fill up your
//config:	  entire filesystem, which may cause your system to
//config:	  break badly.
//config:
//config:config FEATURE_IPC_SYSLOG_BUFFER_SIZE
//config:	int "Circular buffer size in Kbytes (minimum 4KB)"
//config:	default 16
//config:	range 4 2147483647
//config:	depends on FEATURE_IPC_SYSLOG
//config:	help
//config:	  This option sets the size of the circular buffer
//config:	  used to record system log messages.
//config:
//config:config FEATURE_KMSG_SYSLOG
//config:	bool "Linux kernel printk buffer support"
//config:	default y
//config:	depends on SYSLOGD
//config:	select PLATFORM_LINUX
//config:	help
//config:	  When you enable this feature, the syslogd utility will
//config:	  write system log message to the Linux kernel's printk buffer.
//config:	  This can be used as a smaller alternative to the syslogd IPC
//config:	  support, as klogd and logread aren't needed.
//config:
//config:	  NOTICE: Syslog facilities in log entries needs kernel 3.5+.
//config:config FEATURE_DB_SYSLOG
//config:	bool "Redis log support"
//config:	default y
//config:	depends on SYSLOGD
//config:	help
//config:	  When you enable this feature, the syslogd utility can
//config:	  be used to send system log messages to redis database
//config:	  connected via a network. This allows the redis
//config:	  database to log all the system messages, which can be
//config:	  terribly useful for other redis client side program
//config:	  cables you use.

//applet:IF_SYSLOGD(APPLET(syslogd, BB_DIR_SBIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_SYSLOGD) += syslogd_and_logger.o

//usage:#define syslogd_trivial_usage
//usage:       "[OPTIONS]"
//usage:#define syslogd_full_usage "\n\n"
//usage:       "System logging utility\n"
//usage:	IF_NOT_FEATURE_SYSLOGD_CFG(
//usage:       "(this version of syslogd ignores /etc/syslog.conf)\n"
//usage:	)
//usage:     "\n	-n		Run in foreground"
//usage:	IF_FEATURE_REMOTE_LOG(
//usage:     "\n	-R HOST[:PORT:NIF]	Log to HOST:PORT through NIF (default PORT:514)"
//usage:     "\n	-L		Log locally and via network (default is network only if -R)"
//usage:	)
//usage:	IF_FEATURE_IPC_SYSLOG(
/* NB: -Csize shouldn't have space (because size is optional) */
//usage:     "\n	-C[size_kb]	Log to shared mem buffer (use logread to read it)"
//usage:	)
//usage:	IF_FEATURE_KMSG_SYSLOG(
//usage:     "\n	-K		Log to kernel printk buffer (use dmesg to read it)"
//usage:	)
//usage:     "\n	-O FILE		Log to FILE (default: /var/log/messages, stdout if -)"
//usage:	IF_FEATURE_ROTATE_LOGFILE(
//usage:     "\n	-s SIZE		Max size (KB) before rotation (default:200KB, 0=off)"
//usage:     "\n	-b N		N rotated logs to keep (default:1, max=99, 0=purge)"
//usage:	)
//usage:     "\n	-l N		Log only messages more urgent than prio N (1-8)"
//usage:     "\n	-S		Smaller output"
//usage:	IF_FEATURE_SYSLOGD_DUP(
//usage:     "\n	-D		Drop duplicates"
//usage:	)
//usage:	IF_FEATURE_SYSLOGD_CFG(
//usage:     "\n	-f FILE		Use FILE as config (default:/etc/syslog.conf)"
//usage:	)
/* //usage:  "\n	-m MIN		Minutes between MARK lines (default:20, 0=off)" */
//usage:	IF_FEATURE_DB_SYSLOG(
//usage:     "\n	-E REIDS_HOST:PORT:PWD	Log to Redis (default:0.0.0.0:6379:NOPWD)"
//usage:	)
//usage:
//usage:#define syslogd_example_usage
//usage:       "$ syslogd -R masterlog:514\n"
//usage:       "$ syslogd -R 192.168.1.1:601\n"
//usage:       "$ syslogd -E 0.0.0.0:6379:\n"

/*
 * Done in syslogd_and_logger.c:
#include "libbb.h"
#define SYSLOG_NAMES
#define SYSLOG_NAMES_CONST
#include <syslog.h>
*/
#ifndef _PATH_LOG
#define _PATH_LOG	"/dev/log"
#endif

#include <sys/un.h>
#include <sys/uio.h>

#if ENABLE_FEATURE_REMOTE_LOG
#include <netinet/in.h>
#include <net/if.h>
#endif

#if ENABLE_FEATURE_IPC_SYSLOG
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#endif

#if ENABLE_FEATURE_DB_SYSLOG
#include <hiredis/hiredis.h>
#endif

#define DEBUG 0

/* MARK code is not very useful, is bloat, and broken:
 * can deadlock if alarmed to make MARK while writing to IPC buffer
 * (semaphores are down but do_mark routine tries to down them again) */
#undef SYSLOGD_MARK

/* Write locking does not seem to be useful either */
#undef SYSLOGD_WRLOCK

enum {
	MAX_READ = CONFIG_FEATURE_SYSLOGD_READ_BUFFER_SIZE,
	DNS_WAIT_SEC = 2 * 60,
};

/* Semaphore operation structures */
struct shbuf_ds {
	int32_t size;   /* size of data - 1 */
	int32_t tail;   /* end of message list */
	char data[1];   /* data/messages */
};

struct log_content_ds {
	char level[10];
	char brief_key[30];
	char str_time[80];
	char source[64];
	char description[1025];
	int is_alarm;
	int is_business;
	char type[20];
	char parsebuf[2048];
	char out_str[2048];
};

#if ENABLE_FEATURE_REMOTE_LOG
typedef struct {
	int remoteFD;
	unsigned last_dns_resolve;
	len_and_sockaddr *remoteAddr;
	const char remoteHostname[30];
	int remoteHostport;
	const char local_intfc[13];
} remoteHost_t;
#endif

typedef struct logFile_t {
	const char *path;
	int fd;
	time_t last_log_time;
#if ENABLE_FEATURE_ROTATE_LOGFILE
	unsigned size;
	uint8_t isRegular;
#endif
} logFile_t;

#if ENABLE_FEATURE_SYSLOGD_CFG
typedef struct logRule_t {
	uint8_t enabled_facility_priomap[LOG_NFACILITIES];
	struct logFile_t *file;
	struct logRule_t *next;
} logRule_t;
#endif

#if ENABLE_FEATURE_DB_SYSLOG
typedef struct db_config_t {
	char db_host[16];
	short db_port;
	char db_pwd[30];
	redisContext *rds_context;
	unsigned long scnt;
	unsigned long bcnt;
} db_config_t;

#endif

/* Allows us to have smaller initializer. Ugly. */
#define GLOBALS \
	logFile_t logFile;                      \
	/* interval between marks in seconds */ \
	/*int markInterval;*/                   \
	/* level of messages to be logged */    \
	int logLevel;                           \
IF_FEATURE_ROTATE_LOGFILE( \
	/* max size of file before rotation */  \
	unsigned logFileSize;                   \
	/* number of rotated message files */   \
	unsigned logFileRotate;                 \
) \
IF_FEATURE_IPC_SYSLOG( \
	int shmid; /* ipc shared memory id */   \
	int s_semid; /* ipc semaphore id */     \
	int shm_size;                           \
	struct sembuf SMwup[1];                 \
	struct sembuf SMwdn[3];                 \
) \
IF_FEATURE_SYSLOGD_CFG( \
	logRule_t *log_rules; \
) \
IF_FEATURE_KMSG_SYSLOG( \
	int kmsgfd; \
	int primask; \
)	\
IF_FEATURE_DB_SYSLOG ( \
	db_config_t redis_config;	\
)	\

struct init_globals {
	GLOBALS
};

struct globals {
	GLOBALS

#if ENABLE_FEATURE_REMOTE_LOG
	llist_t *remoteHosts;
#endif
#if ENABLE_FEATURE_IPC_SYSLOG
	struct shbuf_ds *shbuf;
#endif
	/* localhost's name. We print only first 64 chars */
	char *hostname;

	/* We recv into recvbuf... */
	char recvbuf[MAX_READ * (1 + ENABLE_FEATURE_SYSLOGD_DUP)];
	/* ...then copy to parsebuf, escaping control chars */
	/* (can grow x2 max) */
	char parsebuf[MAX_READ*2];
	/* ...then sprintf into printbuf, adding timestamp (15 chars),
	 * host (64), fac.prio (20) to the message */
	/* (growth by: 15 + 64 + 20 + delims = ~110) */
	char printbuf[MAX_READ*2 + 128];
};

static const struct init_globals init_data = {
	.logFile = {
		.path = "/var/log/messages",
		.fd = -1,
	},
#ifdef SYSLOGD_MARK
	.markInterval = 20 * 60,
#endif
	.logLevel = 8,
#if ENABLE_FEATURE_ROTATE_LOGFILE
	.logFileSize = 200 * 1024,
	.logFileRotate = 1,
#endif
#if ENABLE_FEATURE_IPC_SYSLOG
	.shmid = -1,
	.s_semid = -1,
	.shm_size = ((CONFIG_FEATURE_IPC_SYSLOG_BUFFER_SIZE)*1024), /* default shm size */
	.SMwup = { {1, -1, IPC_NOWAIT} },
	.SMwdn = { {0, 0}, {1, 0}, {1, +1} },
#endif
#if ENABLE_FEATURE_DB_SYSLOG
	.redis_config = {
		.db_host = "0.0.0.0",
		.db_port = 6379,
		.db_pwd = {0},
		.rds_context = 0,
		.scnt = 0,
		.bcnt = 0,
	},
#endif
};

#define G (*ptr_to_globals)
#define INIT_G() do { \
	SET_PTR_TO_GLOBALS(memcpy(xzalloc(sizeof(G)), &init_data, sizeof(init_data))); \
} while (0)


/* Options */
enum {
	OPTBIT_mark = 0, // -m
	OPTBIT_nofork, // -n
	OPTBIT_outfile, // -O
	OPTBIT_loglevel, // -l
	OPTBIT_small, // -S
	IF_FEATURE_ROTATE_LOGFILE(OPTBIT_filesize   ,)	// -s
	IF_FEATURE_ROTATE_LOGFILE(OPTBIT_rotatecnt  ,)	// -b
	IF_FEATURE_REMOTE_LOG(    OPTBIT_remotelog  ,)	// -R
	IF_FEATURE_REMOTE_LOG(    OPTBIT_locallog   ,)	// -L
	IF_FEATURE_IPC_SYSLOG(    OPTBIT_circularlog,)	// -C
	IF_FEATURE_SYSLOGD_DUP(   OPTBIT_dup        ,)	// -D
	IF_FEATURE_SYSLOGD_CFG(   OPTBIT_cfg        ,)	// -f
	IF_FEATURE_KMSG_SYSLOG(   OPTBIT_kmsg       ,)	// -K
	IF_FEATURE_DB_SYSLOG( 	OPTBIT_dblog		,)	// -E

	OPT_mark        = 1 << OPTBIT_mark    ,
	OPT_nofork      = 1 << OPTBIT_nofork  ,
	OPT_outfile     = 1 << OPTBIT_outfile ,
	OPT_loglevel    = 1 << OPTBIT_loglevel,
	OPT_small       = 1 << OPTBIT_small   ,
	OPT_filesize    = IF_FEATURE_ROTATE_LOGFILE((1 << OPTBIT_filesize   )) + 0,
	OPT_rotatecnt   = IF_FEATURE_ROTATE_LOGFILE((1 << OPTBIT_rotatecnt  )) + 0,
	OPT_remotelog   = IF_FEATURE_REMOTE_LOG(    (1 << OPTBIT_remotelog  )) + 0,
	OPT_locallog    = IF_FEATURE_REMOTE_LOG(    (1 << OPTBIT_locallog   )) + 0,
	OPT_circularlog = IF_FEATURE_IPC_SYSLOG(    (1 << OPTBIT_circularlog)) + 0,
	OPT_dup         = IF_FEATURE_SYSLOGD_DUP(   (1 << OPTBIT_dup        )) + 0,
	OPT_cfg         = IF_FEATURE_SYSLOGD_CFG(   (1 << OPTBIT_cfg        )) + 0,
	OPT_kmsg        = IF_FEATURE_KMSG_SYSLOG(   (1 << OPTBIT_kmsg       )) + 0,
	OPT_dblog       = IF_FEATURE_DB_SYSLOG(   (1 << OPTBIT_dblog       )) + 0,
};
#define OPTION_STR "m:nO:l:S" \
	IF_FEATURE_ROTATE_LOGFILE("s:" ) \
	IF_FEATURE_ROTATE_LOGFILE("b:" ) \
	IF_FEATURE_REMOTE_LOG(    "R:*") \
	IF_FEATURE_REMOTE_LOG(    "L"  ) \
	IF_FEATURE_IPC_SYSLOG(    "C::") \
	IF_FEATURE_SYSLOGD_DUP(   "D"  ) \
	IF_FEATURE_SYSLOGD_CFG(   "f:" ) \
	IF_FEATURE_KMSG_SYSLOG(   "K"  ) \
	IF_FEATURE_DB_SYSLOG( "E::" )
#define OPTION_DECL *opt_m, *opt_l \
	IF_FEATURE_ROTATE_LOGFILE(,*opt_s) \
	IF_FEATURE_ROTATE_LOGFILE(,*opt_b) \
	IF_FEATURE_IPC_SYSLOG(    ,*opt_C = NULL) \
	IF_FEATURE_SYSLOGD_CFG(   ,*opt_f = NULL)	\
	IF_FEATURE_DB_SYSLOG(	,*opt_E = NULL)
#define OPTION_PARAM &opt_m, &(G.logFile.path), &opt_l \
	IF_FEATURE_ROTATE_LOGFILE(,&opt_s) \
	IF_FEATURE_ROTATE_LOGFILE(,&opt_b) \
	IF_FEATURE_REMOTE_LOG(    ,&remoteAddrList) \
	IF_FEATURE_IPC_SYSLOG(    ,&opt_C) \
	IF_FEATURE_SYSLOGD_CFG(   ,&opt_f)	\
	IF_FEATURE_DB_SYSLOG( ,&opt_E)
	
#if ENABLE_FEATURE_SYSLOGD_CFG
static const CODE* find_by_name(char *name, const CODE* c_set)
{
	for (; c_set->c_name; c_set++) {
		if (strcmp(name, c_set->c_name) == 0)
			return c_set;
	}
	return NULL;
}
#endif
static const CODE* find_by_val(int val, const CODE* c_set)
{
	for (; c_set->c_name; c_set++) {
		if (c_set->c_val == val)
			return c_set;
	}
	return NULL;
}

#if ENABLE_FEATURE_SYSLOGD_CFG
static void parse_syslogdcfg(const char *file)
{
	char *t;
	logRule_t **pp_rule;
	/* tok[0] set of selectors */
	/* tok[1] file name */
	/* tok[2] has to be NULL */
	char *tok[3];
	parser_t *parser;

	parser = config_open2(file ? file : "/etc/syslog.conf",
				file ? xfopen_for_read : fopen_for_read);
	if (!parser)
		/* didn't find default /etc/syslog.conf */
		/* proceed as if we built busybox without config support */
		return;

	/* use ptr to ptr to avoid checking whether head was initialized */
	pp_rule = &G.log_rules;
	/* iterate through lines of config, skipping comments */
	while (config_read(parser, tok, 3, 2, "# \t", PARSE_NORMAL | PARSE_MIN_DIE)) {
		char *cur_selector;
		logRule_t *cur_rule;
		/* unexpected trailing token? */
		if (tok[2])
			goto cfgerr;

		cur_rule = *pp_rule = xzalloc(sizeof(*cur_rule));

		cur_selector = tok[0];
		/* iterate through selectors: "kern.info;kern.!err;..." */
		do {
			const CODE *code;
			char *next_selector;
			uint8_t negated_prio; /* "kern.!err" */
			uint8_t single_prio;  /* "kern.=err" */
			uint32_t facmap; /* bitmap of enabled facilities */
			uint8_t primap;  /* bitmap of enabled priorities */
			unsigned i;
			next_selector = strchr(cur_selector, ';');
			if (next_selector)
				*next_selector++ = '\0';
			t = strchr(cur_selector, '.');
			if (!t)
				goto cfgerr;
			*t++ = '\0'; /* separate facility from priority */

			negated_prio = 0;
			single_prio = 0;
			if (*t == '!') {
				negated_prio = 1;
				++t;
			}
			if (*t == '=') {
				single_prio = 1;
				++t;
			}

			/* parse priority */
			if (*t == '*')
				primap = 0xff; /* all 8 log levels enabled */
			else {
				uint8_t priority;
				code = find_by_name(t, prioritynames);
				if (!code)
					goto cfgerr;
				primap = 0;
				priority = code->c_val;
				if (priority == INTERNAL_NOPRI) {
					/* ensure we take "enabled_facility_priomap[fac] &= 0" branch below */
					negated_prio = 1;
				} else {
					priority = 1 << priority;
					do {
						primap |= priority;
						if (single_prio)
							break;
						priority >>= 1;
					} while (priority);
					if (negated_prio)
						primap = ~primap;
				}
			}

			/* parse facility */
			if (*cur_selector == '*')
				facmap = (1<<LOG_NFACILITIES) - 1;
			else {
				char *next_facility;
				facmap = 0;
				t = cur_selector;
				/* iterate through facilities: "kern,daemon.<priospec>" */
				do {
					next_facility = strchr(t, ',');
					if (next_facility)
						*next_facility++ = '\0';
					code = find_by_name(t, facilitynames);
					if (!code)
						goto cfgerr;
					/* "mark" is not a real facility, skip it */
					if (code->c_val != INTERNAL_MARK)
						facmap |= 1<<(LOG_FAC(code->c_val));
					t = next_facility;
				} while (t);
			}

			/* merge result with previous selectors */
			for (i = 0; i < LOG_NFACILITIES; ++i) {
				if (!(facmap & (1<<i)))
					continue;
				if (negated_prio)
					cur_rule->enabled_facility_priomap[i] &= primap;
				else
					cur_rule->enabled_facility_priomap[i] |= primap;
			}
			cur_selector = next_selector;
		} while (cur_selector);

		/* check whether current file name was mentioned in previous rules or
		 * as global logfile (G.logFile).
		 */
		if (strcmp(G.logFile.path, tok[1]) == 0) {
			cur_rule->file = &G.logFile;
			goto found;
		}
		/* temporarily use cur_rule as iterator, but *pp_rule still points
		 * to currently processing rule entry.
		 * NOTE: *pp_rule points to the current (and last in the list) rule.
		 */
		for (cur_rule = G.log_rules; cur_rule != *pp_rule; cur_rule = cur_rule->next) {
			if (strcmp(cur_rule->file->path, tok[1]) == 0) {
				/* found - reuse the same file structure */
				(*pp_rule)->file = cur_rule->file;
				cur_rule = *pp_rule;
				goto found;
			}
		}
		cur_rule->file = xzalloc(sizeof(*cur_rule->file));
		cur_rule->file->fd = -1;
		cur_rule->file->path = xstrdup(tok[1]);
 found:
		pp_rule = &cur_rule->next;
	}
	config_close(parser);
	return;

 cfgerr:
	bb_error_msg_and_die("error in '%s' at line %d",
			file ? file : "/etc/syslog.conf",
			parser->lineno);
}
#endif

/* circular buffer variables/structures */
#if ENABLE_FEATURE_IPC_SYSLOG

#if CONFIG_FEATURE_IPC_SYSLOG_BUFFER_SIZE < 4
#error Sorry, you must set the syslogd buffer size to at least 4KB.
#error Please check CONFIG_FEATURE_IPC_SYSLOG_BUFFER_SIZE
#endif

/* our shared key (syslogd.c and logread.c must be in sync) */
enum { KEY_ID = 0x414e4547 }; /* "GENA" */

static void ipcsyslog_cleanup(void)
{
	if (G.shmid != -1) {
		shmdt(G.shbuf);
	}
	if (G.shmid != -1) {
		shmctl(G.shmid, IPC_RMID, NULL);
	}
	if (G.s_semid != -1) {
		semctl(G.s_semid, 0, IPC_RMID, 0);
	}
}

static void ipcsyslog_init(void)
{
	if (DEBUG)
		printf("shmget(%x, %d,...)\n", (int)KEY_ID, G.shm_size);

	G.shmid = shmget(KEY_ID, G.shm_size, IPC_CREAT | 0644);
	if (G.shmid == -1) {
		bb_perror_msg_and_die("shmget");
	}

	G.shbuf = shmat(G.shmid, NULL, 0);
	if (G.shbuf == (void*) -1L) { /* shmat has bizarre error return */
		bb_perror_msg_and_die("shmat");
	}

	memset(G.shbuf, 0, G.shm_size);
	G.shbuf->size = G.shm_size - offsetof(struct shbuf_ds, data) - 1;
	/*G.shbuf->tail = 0;*/

	/* we'll trust the OS to set initial semval to 0 (let's hope) */
	G.s_semid = semget(KEY_ID, 2, IPC_CREAT | IPC_EXCL | 1023);
	if (G.s_semid == -1) {
		if (errno == EEXIST) {
			G.s_semid = semget(KEY_ID, 2, 0);
			if (G.s_semid != -1)
				return;
		}
		bb_perror_msg_and_die("semget");
	}
}

/* Write message to shared mem buffer */
static void log_to_shmem(const char *msg)
{
	int old_tail, new_tail;
	int len;
	if (semop(G.s_semid, G.SMwdn, 3) == -1) {
		bb_perror_msg_and_die("SMwdn");
	}

	/* Circular Buffer Algorithm:
	 * --------------------------
	 * tail == position where to store next syslog message.
	 * tail's max value is (shbuf->size - 1)
	 * Last byte of buffer is never used and remains NUL.
	 */
	len = strlen(msg) + 1; /* length with NUL included */
 again:
	old_tail = G.shbuf->tail;
	new_tail = old_tail + len;
	if (new_tail < G.shbuf->size) {
		/* store message, set new tail */
		memcpy(G.shbuf->data + old_tail, msg, len);
		G.shbuf->tail = new_tail;
	} else {
		/* k == available buffer space ahead of old tail */
		int k = G.shbuf->size - old_tail;
		/* copy what fits to the end of buffer, and repeat */
		memcpy(G.shbuf->data + old_tail, msg, k);
		msg += k;
		len -= k;
		G.shbuf->tail = 0;
		goto again;
	}
	if (semop(G.s_semid, G.SMwup, 1) == -1) {
		bb_perror_msg_and_die("SMwup");
	}
	if (DEBUG)
		printf("tail:%d\n", G.shbuf->tail);
}
#else
static void ipcsyslog_cleanup(void) {}
static void ipcsyslog_init(void) {}
void log_to_shmem(const char *msg);
#endif /* FEATURE_IPC_SYSLOG */

#if ENABLE_FEATURE_DB_SYSLOG
static void db_ctx_cleanup(void)
{
	bb_perror_msg("db_ctx_cleanup");
	if(G.redis_config.rds_context)redisFree (G.redis_config.rds_context);
	return;
}

static int db_ctx_init(void) 
{
	G.redis_config.rds_context = redisConnect (G.redis_config.db_host, G.redis_config.db_port);
    if (G.redis_config.rds_context == NULL ||  G.redis_config.rds_context->err)
    {
        if (G.redis_config.rds_context == NULL)
        {
			bb_perror_msg("Redis conn err,%s %d,Can't allocate redis context", G.redis_config.db_host, G.redis_config.db_port);
			return -1;
        }
        else
        {
			bb_perror_msg("Redis conn err,%s %d, %s", G.redis_config.db_host, G.redis_config.db_port,G.redis_config.rds_context->errstr);
            redisFree (G.redis_config.rds_context);
			return -1;
        }
    }
    else
    {
		if(strlen(G.redis_config.db_pwd))
		{
			redisReply * reply = redisCommand(G.redis_config.rds_context, "AUTH %s", G.redis_config.db_pwd);
			if(strcmp(reply->str,"OK"))
			{
				freeReplyObject(reply);
				bb_perror_msg("Redis auth err,%s.", G.redis_config.db_pwd);
				return -1;
			}
			freeReplyObject(reply);
		}
	}
	return 0;
}
void log_to_db(char* level, char* brief_key, char* time, char* source, char* description, int is_alarm, int is_business)
{
	redisReply *reply = 0;
	if(is_alarm)
	{
		reply = (redisReply *)redisCommand(G.redis_config.rds_context, "INCR blog_counter");
		if (reply == NULL) {
			return;
		}
		G.redis_config.bcnt = reply->integer;
		freeReplyObject(reply);
		reply = (redisReply*)redisCommand(G.redis_config.rds_context, "hmset blog:%lld level %s type %s time %s source %s desc %s", 
       	G.redis_config.bcnt, level, brief_key, time, source, description);
	}
	else if (is_business)
	{
		// 发送 INCR 命令获取自增数据
    	reply = (redisReply *)redisCommand(G.redis_config.rds_context, "INCR nlog_counter");
		if (reply == NULL) {
			return;
		}
		long long n_counter = reply->integer;
		freeReplyObject(reply);
		reply = (redisReply*)redisCommand(G.redis_config.rds_context, "hmset nlog:%lld level %s type %s time %s source %s desc %s", 
       	n_counter, level, brief_key, time, source, description);
	}
	else
	{
		reply = (redisReply *)redisCommand(G.redis_config.rds_context, "INCR slog_counter");
		if (reply == NULL) {
			return;
		}
		G.redis_config.scnt = reply->integer;
		freeReplyObject(reply);
		reply = (redisReply*)redisCommand(G.redis_config.rds_context, "hmset slog:%lld level %s type %s time %s source %s desc %s", 
       	G.redis_config.scnt, level, brief_key, time, source, description);
	}
		
    if(reply == NULL)
    {
        return;
    }
    freeReplyObject(reply);
}
#else
static void db_ctx_cleanup(void){}
static int db_ctx_init(void) {return 0;}
void log_to_db(char* level, char* brief_key, char* time, char* source, char* description, int is_alarm){}
#endif /* FEATURE_DB_SYSLOG */

#if ENABLE_FEATURE_KMSG_SYSLOG
static void kmsg_init(void)
{
	G.kmsgfd = xopen("/dev/kmsg", O_WRONLY);

	/*
	 * kernel < 3.5 expects single char printk KERN_* priority prefix,
	 * from 3.5 onwards the full syslog facility/priority format is supported
	 */
	if (get_linux_version_code() < KERNEL_VERSION(3,5,0))
		G.primask = LOG_PRIMASK;
	else
		G.primask = -1;
}

static void kmsg_cleanup(void)
{
	if (ENABLE_FEATURE_CLEAN_UP)
		close(G.kmsgfd);
}

/* Write message to /dev/kmsg */
static void log_to_kmsg(int pri, const char *msg)
{
	/*
	 * kernel < 3.5 expects single char printk KERN_* priority prefix,
	 * from 3.5 onwards the full syslog facility/priority format is supported
	 */
	pri &= G.primask;

	full_write(G.kmsgfd, G.printbuf, sprintf(G.printbuf, "<%d>%s\n", pri, msg));
}
#else
static void kmsg_init(void) {}
static void kmsg_cleanup(void) {}
static void log_to_kmsg(int pri UNUSED_PARAM, const char *msg UNUSED_PARAM) {}
#endif /* FEATURE_KMSG_SYSLOG */

/* Print a message to the log file. */
static void log_locally(time_t now, char *msg, logFile_t *log_file)
{
#ifdef SYSLOGD_WRLOCK
	struct flock fl;
#endif
	int len = strlen(msg);

	/* fd can't be 0 (we connect fd 0 to /dev/log socket) */
	/* fd is 1 if "-O -" is in use */
	if (log_file->fd > 1) {
		/* Reopen log files every second. This allows admin
		 * to delete the files and not worry about restarting us.
		 * This costs almost nothing since it happens
		 * _at most_ once a second for each file, and happens
		 * only when each file is actually written.
		 */
		if (!now)
			now = time(NULL);
		if (log_file->last_log_time != now) {
			log_file->last_log_time = now;
			close(log_file->fd);
			goto reopen;
		}
	}
	else if (log_file->fd == 1) {
		/* We are logging to stdout: do nothing */
	}
	else {
		if (LONE_DASH(log_file->path)) {
			log_file->fd = 1;
			/* log_file->isRegular = 0; - already is */
		} else {
 reopen:
			log_file->fd = open(log_file->path, O_WRONLY | O_CREAT
					| O_NOCTTY | O_APPEND | O_NONBLOCK,
					0666);
			if (log_file->fd < 0) {
				/* cannot open logfile? - print to /dev/console then */
				int fd = device_open(DEV_CONSOLE, O_WRONLY | O_NOCTTY | O_NONBLOCK);
				if (fd < 0)
					fd = 2; /* then stderr, dammit */
				full_write(fd, msg, len);
				if (fd != 2)
					close(fd);
				return;
			}
#if ENABLE_FEATURE_ROTATE_LOGFILE
			{
				struct stat statf;
				log_file->isRegular = (fstat(log_file->fd, &statf) == 0 && S_ISREG(statf.st_mode));
				/* bug (mostly harmless): can wrap around if file > 4gb */
				log_file->size = statf.st_size;
			}
#endif
		}
	}

#ifdef SYSLOGD_WRLOCK
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 1;
	fl.l_type = F_WRLCK;
	fcntl(log_file->fd, F_SETLKW, &fl);
#endif

#if ENABLE_FEATURE_ROTATE_LOGFILE
	if (G.logFileSize && log_file->isRegular && log_file->size > G.logFileSize) {
		if (G.logFileRotate) { /* always 0..99 */
			int i = strlen(log_file->path) + 3 + 1;
			char oldFile[i];
			char newFile[i];
			i = G.logFileRotate - 1;
			/* rename: f.8 -> f.9; f.7 -> f.8; ... */
			while (1) {
				sprintf(newFile, "%s.%d", log_file->path, i);
				if (i == 0) break;
				sprintf(oldFile, "%s.%d", log_file->path, --i);
				/* ignore errors - file might be missing */
				rename(oldFile, newFile);
			}
			/* newFile == "f.0" now */
			rename(log_file->path, newFile);
		}

		/* We may or may not have just renamed the file away;
		 * if we didn't rename because we aren't keeping any backlog,
		 * then it's time to clobber the file. If we did rename it...,
		 * incredibly, if F and F.0 are hardlinks, POSIX _demands_
		 * that rename returns 0 but does not remove F!!!
		 * (hardlinked F/F.0 pair was observed after
		 * power failure during rename()).
		 * So ensure old file is gone in any case:
		 */
		unlink(log_file->path);
#ifdef SYSLOGD_WRLOCK
		fl.l_type = F_UNLCK;
		fcntl(log_file->fd, F_SETLKW, &fl);
#endif
		close(log_file->fd);
		goto reopen;
	}
/* TODO: what to do on write errors ("disk full")? */
	len = full_write(log_file->fd, msg, len);
	if (len > 0)
		log_file->size += len;
#else
	full_write(log_file->fd, msg, len);
#endif

#ifdef SYSLOGD_WRLOCK
	fl.l_type = F_UNLCK;
	fcntl(log_file->fd, F_SETLKW, &fl);
#endif
}

static void parse_fac_prio_20(int pri, char *res20)
{
	const CODE *c_pri, *c_fac;

	c_fac = find_by_val(LOG_FAC(pri) << 3, facilitynames);
	if (c_fac) {
		c_pri = find_by_val(LOG_PRI(pri), prioritynames);
		if (c_pri) {
			snprintf(res20, 20, "%s/%s", c_fac->c_name, c_pri->c_name);
			return;
		}
	}
	snprintf(res20, 20, "<%d>", pri);
}

/* len parameter is used only for "is there a timestamp?" check.
 * NB: some callers cheat and supply len==0 when they know
 * that there is no timestamp, short-circuiting the test. */
static void timestamp_and_log(int pri, char *msg, int len)
{
	char *timestamp = 0;
	char str_time[100] = {0};
	time_t now;
	struct tm *p;
	/* Jan 18 00:11:22 msg... */
	/* 01234567890123456 */
	if (len < 16 || msg[3] != ' ' || msg[6] != ' '
	 || msg[9] != ':' || msg[12] != ':' || msg[15] != ' '
	) {
		time(&now);
		p = localtime(&now);
		strftime(str_time, sizeof(str_time), "%Y/%m/%d %H:%M:%S", p);
	} else {
		timestamp = msg;
		timestamp[15] = '\0';
		msg += 16;
		time(&now);
		p = localtime(&now);
		strftime(str_time, sizeof(str_time), "%Y/%m/%d %H:%M:%S", p);
	}
	
	if (option_mask32 & OPT_kmsg) {
		log_to_kmsg(pri, msg);
		return;
	}

#if ENABLE_FEATURE_DB_SYSLOG
	if ((option_mask32 & OPT_dblog)) { 
		char msg_cpy[1024] = {0};
		snprintf(msg_cpy, 1024, "%s", msg);
		char* time = str_time;
		char level[10] = {0};
		char type[20] = {0};
		CODE *c_pri = 0, *c_fac;
		c_fac = find_by_val(LOG_FAC(pri) << 3, facilitynames);
		if (c_fac) {
			snprintf(type,20,"%s",c_fac->c_name);
			c_pri = find_by_val(LOG_PRI(pri), prioritynames);
			if (c_pri) 
				snprintf(level, 10, "%s", c_pri->c_name);
			else
				snprintf(level, 10, "%d", pri);
		}
		else
			snprintf(level, 10, "%d", pri);
		char brief_key[30] = {0}, *msg_cursor;
		size_t  brief_len = 0;
		msg_cursor = msg_cpy;
		brief_len = strcspn(msg_cursor, ":");
		msg_cursor += brief_len;
		char description[1025] = {0};
		int is_alarm = 0;
		if(*msg_cursor == ':' && *(msg_cursor+1)==' ')
		{
			char* old_val = msg_cursor;
			*msg_cursor++ = '\0';
			//msg_cursor++;
			snprintf(brief_key, 30, "%s", msg_cpy);
			
			snprintf(description, 1024, "%s", msg_cursor+1);
			*old_val = ':';
			if(*(msg_cursor+1) == '#')
			{
				//bb_perror_msg("parse #");
				//#等级|模块名|摘要|详细
				char *level_itr = msg_cursor+2;
				size_t level_len = 0;
				level_len = strcspn(level_itr, "|");
				if(*(level_itr+level_len) == '|')
				{
					//bb_perror_msg("parse | 0");
					level_itr += level_len;
					old_val = level_itr;
					*level_itr++='\0';
					//type_itr++;
					snprintf(level,10,"%s",msg_cursor+2);
					//bb_perror_msg("type %s", type);
					*old_val = '|';

					char *type_itr = level_itr;
					size_t type_len = 0;
					type_len = strcspn(type_itr, "|");
					if(*(type_itr+type_len) == '|')
					{
						//bb_perror_msg("parse | 1");
						type_itr+=type_len;
						old_val = type_itr;
						*type_itr++='\0';
						//type_itr++;
						snprintf(type,20,"%s",level_itr);
						//bb_perror_msg("type %s", type);
						*old_val = '|';

						char* brief_itr = type_itr;
						brief_len = 0;
						brief_len = strcspn(brief_itr, "|");
						if(*(brief_itr+brief_len) == '|')
						{
							//bb_perror_msg("parse | 2");
							is_alarm = 1;
							brief_itr += brief_len;
							old_val = brief_itr;
							*brief_itr++='\0';
							//brief_itr++;
							snprintf(brief_key,30,"%s",type_itr);
							*old_val = '|';
							memset(description, 0, sizeof(description));
							snprintf(description, 1024, "%s", brief_itr);
						}
					}
				}
			}
		}
		else
		{
			snprintf(brief_key, 16, "%s", msg);
			snprintf(description, 1024, "%s", msg);
		}
		int is_business = 0;
		char source[64] = {0};
		//非标准告警打入log日志 
		//具体:等级8的告警是acl的业务日志,由于拿不到业务日志的key序号所以先存入redis的slog里
		if(is_alarm && level[0] == '8') is_business = 1;
		if(!is_alarm || is_business)
		{
			memset(level, 0 , sizeof(level));
			is_alarm = 0;
			//is_alarm = c_pri ? (LOG_PRI(pri) <= LOG_WARNING ? 1 : 0) : (pri <= LOG_WARNING ? 1 : 0);
			if(c_pri)
			{
				snprintf(source, 64, "%.64s %%7x%%01%s/%d/%s",  G.hostname, type, LOG_PRI(pri), brief_key);
				snprintf(level, 10, "%s", c_pri->c_name);
			}
			else
			{
				snprintf(source, 64, "%.64s %%7x%%01%s/%d/%s",  G.hostname, type, pri, brief_key);
				snprintf(level, 10, "%d", pri);
			}	
		}
		else
		{//标准告警从告警的第一个字段获取告警等级
			snprintf(source, 64, "%.64s %%7x%%01%s/%s/%s",  G.hostname, type, level, brief_key);
		}
		log_to_db(level, brief_key, time, source, description, is_alarm, is_business);
		return;
	}
#endif

	if (option_mask32 & OPT_small)
		sprintf(G.printbuf, "%s %s\n", str_time, msg);
	else {
		char res[20];
		parse_fac_prio_20(pri, res);
		if(timestamp)sprintf(G.printbuf, "%s %.64s %%7x%%01%s/%s,at %s\n", str_time, G.hostname, res, msg, timestamp);
		else sprintf(G.printbuf, "%s %.64s %%7x%%01%s/%s\n", str_time, G.hostname, res, msg);
	}

	/* Log message locally (to file or shared mem) */
#if ENABLE_FEATURE_SYSLOGD_CFG
	{
		bool match = 0;
		logRule_t *rule;
		uint8_t facility = LOG_FAC(pri);
		uint8_t prio_bit = 1 << LOG_PRI(pri);

		for (rule = G.log_rules; rule; rule = rule->next) {
			if (rule->enabled_facility_priomap[facility] & prio_bit) {
				log_locally(now, G.printbuf, rule->file);
				match = 1;
			}
		}
		if (match)
			return;
	}
#endif
	if (LOG_PRI(pri) < G.logLevel) {
#if ENABLE_FEATURE_IPC_SYSLOG
		if ((option_mask32 & OPT_circularlog) && G.shbuf) {
			log_to_shmem(G.printbuf);
			return;
		}
#endif

printf("%s,%s\n", G.printbuf, G.logFile.path);
		log_locally(now, G.printbuf, &G.logFile);
	}
}

static void timestamp_and_log_internal(const char *msg)
{
	/* -L, or no -R */
	if (ENABLE_FEATURE_REMOTE_LOG && !(option_mask32 & OPT_locallog))
		return;
	timestamp_and_log(LOG_SYSLOG | LOG_INFO, (char*)msg, 0);
}

static void split_recvbuf_as_syslog(char *tmpbuf, int len, struct log_content_ds* lds)
{
	char *p = tmpbuf;
	tmpbuf += len;
	char oval = tmpbuf;
	*tmpbuf = '\0';
//bb_perror_msg("enter %s\n",p);
	while (p < tmpbuf) {
		char c;
		char *q = lds->parsebuf;
		int pri = (LOG_USER | LOG_NOTICE);

		if (*p == '<') {
			/* Parse the magic priority number */
			pri = bb_strtou(p + 1, &p, 10);
			if (*p == '>')
				p++;
			if (pri & ~(LOG_FACMASK | LOG_PRIMASK))
				pri = (LOG_USER | LOG_NOTICE);
		}

		while ((c = *p++)) {
			if (c == '\n')
				c = ' ';
			if (!(c & ~0x1f) && c != '\t') {
				*q++ = '^';
				c += '@'; 
			}
			*q++ = c;
		}
		*q = '\0';
//bb_perror_msg("enter2 %s\n",lds->parsebuf);
	char* msg = lds->parsebuf;
	int msglen = q - lds->parsebuf;
	char *timestamp = 0;
	time_t now;
	struct tm *p;
	/* Jan 18 00:11:22 msg... */
	/* 01234567890123456 */
	if (msglen < 16 || msg[3] != ' ' || msg[6] != ' '
	 || msg[9] != ':' || msg[12] != ':' || msg[15] != ' '
	) {
		time(&now);
		p = localtime(&now);
		strftime(lds->str_time, sizeof(lds->str_time), "%Y/%m/%d %H:%M:%S", p);
	} else {
		timestamp = msg;
		timestamp[15] = '\0';
		msg += 16;
		time(&now);
		p = localtime(&now);
		strftime(lds->str_time, sizeof(lds->str_time), "%Y/%m/%d %H:%M:%S", p);
	}
//bb_perror_msg("time: %s\n", timestamp);

		char msg_cpy[1024] = {0};
		snprintf(msg_cpy, 1024, "%s", msg);
		CODE *c_pri = 0, *c_fac;
		c_fac = find_by_val(LOG_FAC(pri) << 3, facilitynames);
		if (c_fac) {
			snprintf(lds->type, sizeof(lds->type),"%s",c_fac->c_name);
			c_pri = find_by_val(LOG_PRI(pri), prioritynames);
			if (c_pri) 
				snprintf(lds->level, sizeof(lds->level), "%s", c_pri->c_name);
			else
				snprintf(lds->level, sizeof(lds->level), "%d", pri);
		}
		else
			snprintf(lds->level, sizeof(lds->level), "%d", pri);
		char *msg_cursor;
		size_t  brief_len = 0;
		msg_cursor = msg_cpy;
		brief_len = strcspn(msg_cursor, ":");
		msg_cursor += brief_len;
		if(*msg_cursor == ':' && *(msg_cursor+1)==' ')
		{
			char* old_val = msg_cursor;
			*msg_cursor++ = '\0';
			snprintf(lds->brief_key, sizeof(lds->brief_key), "%s", msg_cpy);
			snprintf(lds->description, sizeof(lds->description), "%s", msg_cursor+1);
			*old_val = ':';
			if(*(msg_cursor+1) == '#')
			{
				//bb_perror_msg("parse #");
				//#等级|模块名|摘要|详细
				char *level_itr = msg_cursor+2;
				size_t level_len = 0;
				level_len = strcspn(level_itr, "|");
				if(*(level_itr+level_len) == '|')
				{
					//bb_perror_msg("parse | 0");
					level_itr += level_len;
					old_val = level_itr;
					*level_itr++='\0';
					//type_itr++;
					snprintf(lds->level,10,"%s",msg_cursor+2);
					//bb_perror_msg("type %s", type);
					*old_val = '|';

					char *type_itr = level_itr;
					size_t type_len = 0;
					type_len = strcspn(type_itr, "|");
					if(*(type_itr+type_len) == '|')
					{
						//bb_perror_msg("parse | 1");
						type_itr+=type_len;
						old_val = type_itr;
						*type_itr++='\0';
						//type_itr++;
						snprintf(lds->type,20,"%s",level_itr);
						//bb_perror_msg("type %s", type);
						*old_val = '|';

						char* brief_itr = type_itr;
						brief_len = 0;
						brief_len = strcspn(brief_itr, "|");
						if(*(brief_itr+brief_len) == '|')
						{
							//bb_perror_msg("parse | 2");
							lds->is_alarm = 1;
							brief_itr += brief_len;
							old_val = brief_itr;
							*brief_itr++='\0';
							//brief_itr++;
							snprintf(lds->brief_key,30,"%s",type_itr);
							*old_val = '|';
							memset(lds->description, 0, sizeof(lds->description));
							snprintf(lds->description, 1024, "%s", brief_itr);
						}
					}
				}
			}
		}
		else
		{
			snprintf(lds->brief_key, 16, "%s", msg);
			snprintf(lds->description, 1024, "%s", msg);
		}
//bb_perror_msg("msg: %s\n", msg);
		//非标准告警打入log日志 
		//具体:等级8的告警是acl的业务日志,拿到业务日志的key序号存入redis的nlog里
		if(lds->is_alarm && lds->level[0] == '8') lds->is_business = 1;
		if(!lds->is_alarm || lds->is_business)
		{
			memset(lds->level, 0 , sizeof(lds->level));
			lds->is_alarm = 0;
			//is_alarm = c_pri ? (LOG_PRI(pri) <= LOG_WARNING ? 1 : 0) : (pri <= LOG_WARNING ? 1 : 0);
			if(c_pri)
			{
				snprintf(lds->source, 64, "%.64s %%7x%%01%s/%d/%s",  G.hostname, lds->type, LOG_PRI(pri), lds->brief_key);
				snprintf(lds->level, 10, "%s", c_pri->c_name);
			}
			else
			{
				snprintf(lds->source, 64, "%.64s %%7x%%01%s/%d/%s",  G.hostname, lds->type, pri, lds->brief_key);
				snprintf(lds->level, 10, "%d", pri);
			}
		}
		else
		{//标准告警从告警的第一个字段获取告警等级
			snprintf(lds->source, 64, "%.64s %%7x%%01%s/%s/%s",  G.hostname, lds->type, lds->level, lds->brief_key);
		}
//bb_perror_msg("source: %s\n", lds->source);
		char res[20];
		parse_fac_prio_20(pri, res);
		char rtime[80] = {0};
		strftime(rtime, sizeof(rtime), "%b %d %Y %H:%M:%S", p);
		if(timestamp)sprintf(lds->out_str, "<%d>%s %s:%s,at %s\n", pri, rtime, lds->source, lds->description, timestamp);
		else sprintf(lds->out_str, "<%d>%s %s:%s", pri, rtime, lds->source, lds->description);
//bb_perror_msg("%s", lds->out_str);
	}
	tmpbuf = oval;
}

/* tmpbuf[len] is a NUL byte (set by caller), but there can be other,
 * embedded NULs. Split messages on each of these NULs, parse prio,
 * escape control chars and log each locally. */
static void split_escape_and_log(char *tmpbuf, int len)
{
	char *p = tmpbuf;

	tmpbuf += len;
	while (p < tmpbuf) {
		char c;
		char *q = G.parsebuf;
		int pri = (LOG_USER | LOG_NOTICE);

		if (*p == '<') {
			/* Parse the magic priority number */
			pri = bb_strtou(p + 1, &p, 10);
			if (*p == '>')
				p++;
			if (pri & ~(LOG_FACMASK | LOG_PRIMASK))
				pri = (LOG_USER | LOG_NOTICE);
		}

		while ((c = *p++)) {
			if (c == '\n')
				c = ' ';
			if (!(c & ~0x1f) && c != '\t') {
				*q++ = '^';
				c += '@'; /* ^@, ^A, ^B... */
			}
			*q++ = c;
		}
		*q = '\0';
		/* Now log it */
		timestamp_and_log(pri, G.parsebuf, q - G.parsebuf);
	}
}

#ifdef SYSLOGD_MARK
static void do_mark(int sig)
{
	if (G.markInterval) {
		timestamp_and_log_internal("-- MARK --");
		alarm(G.markInterval);
	}
}
#endif

/* Don't inline: prevent struct sockaddr_un to take up space on stack
 * permanently */
static NOINLINE int create_socket(void)
{
	struct sockaddr_un sunx;
	int sock_fd;
	char *dev_log_name;

	memset(&sunx, 0, sizeof(sunx));
	sunx.sun_family = AF_UNIX;

	/* Unlink old /dev/log or object it points to. */
	/* (if it exists, bind will fail) */
	strcpy(sunx.sun_path, _PATH_LOG);
	dev_log_name = xmalloc_follow_symlinks(_PATH_LOG);
	if (dev_log_name) {
		safe_strncpy(sunx.sun_path, dev_log_name, sizeof(sunx.sun_path));
		free(dev_log_name);
	}
	unlink(sunx.sun_path);

	sock_fd = xsocket(AF_UNIX, SOCK_DGRAM, 0);
	xbind(sock_fd, (struct sockaddr *) &sunx, sizeof(sunx));
	chmod(_PATH_LOG, 0666);

	return sock_fd;
}

#if ENABLE_FEATURE_REMOTE_LOG
static int try_to_resolve_remote(remoteHost_t *rh)
{
	if (!rh->remoteAddr) {
		unsigned now = monotonic_sec();

		/* Don't resolve name too often - DNS timeouts can be big */
		if ((now - rh->last_dns_resolve) < DNS_WAIT_SEC)
			return -1;
		rh->last_dns_resolve = now;
		
		rh->remoteAddr = host2sockaddr(rh->remoteHostname, rh->remoteHostport);
//		bb_perror_msg("try_to_resolve_remote %s, %d\n", rh->remoteHostname, rh->remoteHostport);
		if (!rh->remoteAddr)
			return -1;
	}
	return xsocket(rh->remoteAddr->u.sa.sa_family, SOCK_DGRAM, 0);
	
}
#endif

static void do_syslogd(void) NORETURN;
static void do_syslogd(void)
{
#if ENABLE_FEATURE_REMOTE_LOG
	llist_t *item;
#endif
#if ENABLE_FEATURE_SYSLOGD_DUP
	int last_sz = -1;
	char *last_buf;
	char *recvbuf = G.recvbuf;
#else
#define recvbuf (G.recvbuf)
#endif

	/* Set up signal handlers (so that they interrupt read()) */
	signal_no_SA_RESTART_empty_mask(SIGTERM, record_signo);
	signal_no_SA_RESTART_empty_mask(SIGINT, record_signo);
	//signal_no_SA_RESTART_empty_mask(SIGQUIT, record_signo);
	signal(SIGHUP, SIG_IGN);
#ifdef SYSLOGD_MARK
	signal(SIGALRM, do_mark);
	alarm(G.markInterval);
#endif
	xmove_fd(create_socket(), STDIN_FILENO);

	if (option_mask32 & OPT_circularlog)
		ipcsyslog_init();

	if (option_mask32 & OPT_kmsg)
		kmsg_init();
	if (option_mask32 & OPT_dblog)
	{
		if(db_ctx_init())return;
	}
		

	//timestamp_and_log_internal("syslogd started: BusyBox v" BB_VER);

	while (!bb_got_signal) {
		ssize_t sz;

#if ENABLE_FEATURE_SYSLOGD_DUP
		last_buf = recvbuf;
		if (recvbuf == G.recvbuf)
			recvbuf = G.recvbuf + MAX_READ;
		else
			recvbuf = G.recvbuf;
#endif
 read_again:
		sz = read(STDIN_FILENO, recvbuf, MAX_READ - 1);
		if (sz < 0) {
			if (!bb_got_signal)
				bb_perror_msg("read from %s", _PATH_LOG);
			break;
		}

		/* Drop trailing '\n' and NULs (typically there is one NUL) */
		while (1) {
			if (sz == 0)
				goto read_again;
			/* man 3 syslog says: "A trailing newline is added when needed".
			 * However, neither glibc nor uclibc do this:
			 * syslog(prio, "test")   sends "test\0" to /dev/log,
			 * syslog(prio, "test\n") sends "test\n\0".
			 * IOW: newline is passed verbatim!
			 * I take it to mean that it's syslogd's job
			 * to make those look identical in the log files. */
			if (recvbuf[sz-1] != '\0' && recvbuf[sz-1] != '\n')
				break;
			sz--;
		}
#if ENABLE_FEATURE_SYSLOGD_DUP
		if ((option_mask32 & OPT_dup) && (sz == last_sz))
			if (memcmp(last_buf, recvbuf, sz) == 0)
				continue;
		last_sz = sz;
#endif
	
#if ENABLE_FEATURE_REMOTE_LOG
		if(option_mask32 & OPT_remotelog)
		{
			struct log_content_ds lds = {0};
			split_recvbuf_as_syslog(recvbuf, sz, &lds);
			//告警或业务日志不发送到远端
			if(lds.is_alarm || lds.is_business)
			{
				if(G.redis_config.rds_context);
				else
				{
					db_ctx_init();
				}
				log_to_db(lds.level, lds.brief_key, lds.str_time, lds.source, lds.description, lds.is_alarm, lds.is_business );
				continue;
			}
		
		/* Stock syslogd sends it '\n'-terminated
		 * over network, mimic that */
		recvbuf[sz] = '\n';
		/* We are not modifying log messages in any way before send */
		/* Remote site cannot trust _us_ anyway and need to do validation again */
		for (item = G.remoteHosts; item != NULL; item = item->link) {
			
			remoteHost_t *rh = (remoteHost_t *)item->data;

			if (rh->remoteFD == -1) {
				rh->remoteFD = try_to_resolve_remote(rh);
				if (rh->remoteFD == -1)
					continue;
				struct ifreq nif;
				strncpy(nif.ifr_name, rh->local_intfc, IFNAMSIZ);
				setsockopt(rh->remoteFD, SOL_SOCKET, SO_BINDTODEVICE,(char*)&nif, sizeof(nif));
			}
			/* format recvbuf to new standy syslog format */
			
			/* Send message to remote logger.
			 * On some errors, close and set remoteFD to -1
			 * so that DNS resolution is retried.
			 */
			if ( sendto(rh->remoteFD, lds.out_str, strlen(lds.out_str),
					MSG_DONTWAIT | MSG_NOSIGNAL,
					&(rh->remoteAddr->u.sa), rh->remoteAddr->len) == -1
			) {
				switch (errno) {
				case ECONNRESET:
				case ENOTCONN: /* paranoia */
				case EPIPE:
					close(rh->remoteFD);
					rh->remoteFD = -1;
					free(rh->remoteAddr);
					rh->remoteAddr = NULL;
				}
			}
		}}
#endif
		if (!ENABLE_FEATURE_REMOTE_LOG || (option_mask32 & OPT_locallog)) {
			recvbuf[sz] = '\0'; /* ensure it *is* NUL terminated */
			split_escape_and_log(recvbuf, sz);
		}
	} /* while (!bb_got_signal) */

	//timestamp_and_log_internal("syslogd exiting");
	remove_pidfile(CONFIG_PID_FILE_PATH "/syslogd.pid");
	ipcsyslog_cleanup();
	if (option_mask32 & OPT_kmsg)
		kmsg_cleanup();
	if (option_mask32 & OPT_dblog)
		db_ctx_cleanup();
	kill_myself_with_sig(bb_got_signal);
#undef recvbuf
}

int syslogd_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int syslogd_main(int argc UNUSED_PARAM, char **argv)
{
	int opts;
	char OPTION_DECL;
#if ENABLE_FEATURE_REMOTE_LOG
	llist_t *remoteAddrList = NULL;
	
#endif

	INIT_G();
	sizeof(remoteHost_t);
	/* No non-option params */
	opt_complementary = "=0";
	opts = getopt32(argv, OPTION_STR, OPTION_PARAM);
#if ENABLE_FEATURE_REMOTE_LOG
	while (remoteAddrList) {
		remoteHost_t *rh = xzalloc(sizeof(*rh));
		
	char* remote_cfg_tok[3];
	char* remote_cursor;
	remote_cursor = remote_cfg_tok[0] = llist_pop(&remoteAddrList);
	size_t remote_ip_len = 0;
	remote_ip_len = strcspn(remote_cursor, ":");
	if(remote_ip_len > 30)
	{
		bb_perror_msg("Remote host/ip len must less than 30,got %ld", remote_ip_len);
		return -1;
	}
	else if(*(remote_cursor+remote_ip_len) == ':')
	{
		remote_cursor += remote_ip_len;
		*remote_cursor++='\0';
		snprintf(rh->remoteHostname,30,"%s",remote_cfg_tok[0]);
	}
	else
	{
		return -1;
	}
	remote_cfg_tok[1] = remote_cursor;
	size_t remote_port_len = 0;
	remote_port_len = strcspn(remote_cursor, ":");
	if(*(remote_cursor+remote_port_len) == ':')
	{
		remote_cursor += remote_port_len;
		*remote_cursor++='\0';
		rh->remoteHostport = xatou_range(remote_cfg_tok[1], 1, 65535);
	}
	else
	{
		return -1;
	}
	remote_cfg_tok[2] = remote_cursor;
	size_t remote_nif_len = 0;
	remote_nif_len = strcspn(remote_cursor, " \t\n\r\0");
	if(remote_nif_len > 13)
	{
		bb_perror_msg("Output interface name len must less than 13,got %ld", remote_nif_len);
		return -1;	
	}
	else if(remote_nif_len)
	{
		remote_cursor += remote_nif_len;
		*remote_cursor++='\0';
		strcpy(rh->local_intfc, remote_cfg_tok[2]);
	
	}
	else
	{
		return -1;
	}
		rh->remoteFD = -1;
		rh->last_dns_resolve = monotonic_sec() - DNS_WAIT_SEC - 1;
		llist_add_to(&G.remoteHosts, rh);
	}
#endif

#ifdef SYSLOGD_MARK
	if (opts & OPT_mark) // -m
		G.markInterval = xatou_range(opt_m, 0, INT_MAX/60) * 60;
#endif
	//if (opts & OPT_nofork) // -n
	//if (opts & OPT_outfile) // -O
	if (opts & OPT_loglevel) // -l
		G.logLevel = xatou_range(opt_l, 1, 8);
	//if (opts & OPT_small) // -S
#if ENABLE_FEATURE_ROTATE_LOGFILE
	if (opts & OPT_filesize) // -s
		G.logFileSize = xatou_range(opt_s, 0, INT_MAX/1024) * 1024;
	if (opts & OPT_rotatecnt) // -b
		G.logFileRotate = xatou_range(opt_b, 0, 99);
#endif
#if ENABLE_FEATURE_IPC_SYSLOG
	if (opt_C) // -Cn
		G.shm_size = xatoul_range(opt_C, 4, INT_MAX/1024) * 1024;
#endif
#if ENABLE_FEATURE_DB_SYSLOG
if (opt_E)
{
	bb_perror_msg("opt_E %s",opt_E);
	char* db_cfg_tok[3];
	char* db_cursor;
	db_cfg_tok[0] = db_cursor = opt_E;
	size_t db_ip_len = 0;
	db_ip_len = strcspn(db_cursor, ":");
	if(db_ip_len > 16)
	{
		bb_perror_msg("Redis host ip len must less than 16,got %ld", db_ip_len);
		return -1;
	}
	else if(*(db_cursor+db_ip_len) == ':')
	{
		db_cursor += db_ip_len;
		*db_cursor++='\0';
		strcpy(G.redis_config.db_host, db_cfg_tok[0]);
	}
	else
	{
		return -1;
	}
	db_cfg_tok[1] = db_cursor;
	size_t db_port_len = 0;
	db_port_len = strcspn(db_cursor, ":");
	if(*(db_cursor+db_port_len) == ':')
	{
		db_cursor += db_port_len;
		*db_cursor++='\0';
		G.redis_config.db_port = xatou_range(db_cfg_tok[1], 1000, 65535);
	}
	else
	{
		return -1;
	}
	db_cfg_tok[2] = db_cursor;
	size_t db_pwd_len = 0;
	db_pwd_len = strcspn(db_cursor, " \t\n\r\0");
	if(db_pwd_len > 30)
	{
		bb_perror_msg("Redis password len must less than 30,got %ld", db_pwd_len);
		return -1;	
	}
	else
	{
		if(db_pwd_len)
		{
			db_cursor += db_pwd_len;
			*db_cursor++='\0';
			strcpy(G.redis_config.db_pwd, db_cfg_tok[2]);
		}
	}
	
}
#endif
	/* If they have not specified remote logging, then log locally */
	if (ENABLE_FEATURE_REMOTE_LOG && !(opts & OPT_remotelog)) // -R
		option_mask32 |= OPT_locallog;
#if ENABLE_FEATURE_SYSLOGD_CFG
	parse_syslogdcfg(opt_f);
#endif

	/* Store away localhost's name before the fork */
	G.hostname = safe_gethostname();
	*strchrnul(G.hostname, '.') = '\0';

	if (!(opts & OPT_nofork)) {
		bb_daemonize_or_rexec(DAEMON_CHDIR_ROOT, argv);
	}

	//umask(0); - why??
	write_pidfile(CONFIG_PID_FILE_PATH "/syslogd.pid");

	do_syslogd();
	/* return EXIT_SUCCESS; */
}

/* Clean up. Needed because we are included from syslogd_and_logger.c */
#undef DEBUG
#undef SYSLOGD_MARK
#undef SYSLOGD_WRLOCK
#undef G
#undef GLOBALS
#undef INIT_G
#undef OPTION_STR
#undef OPTION_DECL
#undef OPTION_PARAM
