/*
 * sfs.h
 *
 * The main SFS defines, declarations and function prototypes.
 *
 * Copyright 1998 Michal Svec <rebel@atrey.karlin.mff.cuni.cz>
 * Copyright 1998 Vaclav Petricek <petricek@mail.kolej.mff.cuni.cz>
 *
 */

#ifndef _SFS_H
#define _SFS_H

#include <sys/types.h>
#include <asm/stat.h>

/*
 * SFS constants and macros
 *
 */

#define SFS_D_QUEUE_ID		12347				/* ??? */
#define SFS_MESSAGE		12347				/* ??? */

#define SFS_D_QUEUE_PERM	0622
#define SFS_R_QUEUE_PERM	0222
#define SFS_C_QUEUE_PERM	0600

#define SFS_MSG_SIZE		sizeof(struct sfs_message)
#define SFS_MSG_MAX		4000				/* !!! */

#define SFS_LOGIN_USERNAME	"Login: "
#define SFS_LOGIN_PASSWD	"Password: "
#define SFS_PASSWD_OLD		"Old password: "
#define SFS_PASSWD_NEW		"New password: "
#define SFS_DELIMITER		":"

#define SFS_MAX_USERS		100
#define SFS_MAX_FILES		256

#define SFS_MAX_USER		20
#define SFS_MAX_PASS		20
#define SFS_MAX_KEY		1500
#define SFS_MAX_PATH		1500
#define SFS_MAX_BUF_SIZE	8

#define SFS_REPLY_OK		0
#define SFS_REPLY_FAIL		1
#define SFS_REPLY_ENCRYPTED	2

#define SFS_ERRNO		12347

#define SFS_MODE		0100000

#define SFS_AUTH_KEY_SIZE	5
#define SFS_FILE_KEY_SIZE	20

#define SFS_DIR			"/etc/sfs"
#define SFS_PASSWD_FILE		SFS_DIR"/passwd"
#define SFS_SHADOW_FILE		SFS_DIR"/shadow"
#define SFS_GROUPS_FILE		SFS_DIR"/groups"
#define SFS_GSHADOW_FILE	SFS_DIR"/gshadow"
#define SFS_ALL_FILE		SFS_DIR"/all"
#define SFS_ASHADOW_FILE	SFS_DIR"/ashadow"
#define SFS_LOGIN_FILE		SFS_DIR"/login"
#define SFS_UDIR_FILE		".sfsdir"
#define SFS_GDIR_FILE		".sfsgdir"
#define SFS_ADIR_FILE		".sfsadir"
#define SFS_SIZES_FILE		".sfssizes"

enum { SFS_STRING_REQ = 1, SFS_OPEN_REQ, SFS_CLOSE_REQ, SFS_READ_REQ,
       SFS_WRITE_REQ, SFS_CHMOD_REQ, SFS_FCHMOD_REQ, SFS_LOGIN_REQ,
       SFS_REPLY_REQ, SFS_IS_REQ, SFS_CHPASS_REQ, SFS_DUMP_REQ,
       SFS_GETSIZE_REQ, SFS_SETSIZE_REQ };

/*
 * SFS structures
 *
 */

  // Get or set size of a file
struct sfs_size_request {
  pid_t pid;
  uid_t uid;
  int fd;
  off_t size;
};

  // Open a file
struct sfs_open_request {
  char dir[SFS_MAX_PATH];
  char name[SFS_MAX_PATH];
  pid_t pid;
  uid_t uid;
  gid_t gid;
  int fd;
};


struct sfs_is_request {
  int fd;
  pid_t pid;
};


  // Close a file
struct sfs_close_request {
  int fd;
  pid_t pid;
};


  // Read data from encrypted file
struct sfs_read_request {
  int fd;
  pid_t pid;
  char buf[SFS_MAX_BUF_SIZE];
  size_t count;
  char last;
};


  // Write data to encrypted file
struct sfs_write_request {
  int fd;
  pid_t pid;
  char buf[SFS_MAX_BUF_SIZE];
  size_t count;
};


  // Login as specified user
struct sfs_login_request {
  char name[SFS_MAX_USER];
  char key[SFS_MAX_KEY];
  uid_t uid;
  gid_t gid;
};


  // Change mode of file (encrypted <--> plain)
struct sfs_chmod_request {
  char dir[SFS_MAX_PATH];
  char name[SFS_MAX_PATH];
  uid_t uid;
  gid_t gid;
  mode_t mode;
  mode_t rights;
  off_t size;
};


  // Request to chmod an open file
struct sfs_fchmod_request {
  int fd;
  uid_t uid;
  mode_t mode;
};


  // Change user private key
struct sfs_chpass_request {
  char name[SFS_MAX_USER];
  char key[SFS_MAX_KEY];
  uid_t uid;
  gid_t gid;
};


  // Request to daemon
union sfs_request {
  char sfs_string[SFS_MSG_MAX];
  struct sfs_is_request sfs_is;
  struct sfs_open_request sfs_open;
  struct sfs_close_request sfs_close;
  struct sfs_read_request sfs_read;
  struct sfs_write_request sfs_write;
  struct sfs_login_request sfs_login;
  struct sfs_chpass_request sfs_chpass;
  struct sfs_chmod_request sfs_chmod;
  struct sfs_fchmod_request sfs_fchmod;
  struct sfs_size_request sfs_size;
};


  // Message passed to daemon
struct sfs_message {
  long sfs_req_auth;
  long sfs_req_type;
  int sfs_req_uid;
  int sfs_req_reply_queue;
  union sfs_request sfs_req;
};


  // Structure that is passed through the message queue
struct s_msg {
  long mtype;
  struct sfs_message sfs_msg;
};


  // Opened encrypted file
struct sfs_file {
  pid_t pid;
  int fd;
  char key[SFS_MAX_KEY];
  char dir[SFS_MAX_PATH];
  char name[SFS_MAX_PATH];
  off_t size;
};


  // Logged in user
struct sfs_user {
  char name[SFS_MAX_USER];
  char key[SFS_MAX_KEY];
  uid_t uid;
  gid_t gid;
  char gkey[SFS_MAX_KEY];
  char akey[SFS_MAX_KEY];
};


  // Region of a file
typedef struct sfs_offset {
  off_t offset;
  size_t count;
} sfs_offset;


  // Location of a file = dir + name
typedef struct file_location {
  char * dir;
  char * name;
} file_location;


/*
 * SFS functions
 *
 */

extern int __syscall_fstat( int fd, struct new_stat *stat_buf );
extern int __syscall_stat( const char *path, struct new_stat *stat_buf );

#endif

