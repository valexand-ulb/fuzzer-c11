#ifndef TAR_HEADER_H
#define TAR_HEADER_H

#define NAME_PADDING 0
#define MODE_PADDING 100
#define UID_PADDING 108
#define GID_PADDING 116
#define SIZE_PADDING 124
#define MTIME_PADDING 136
#define CHKSUM_PADDING 148
#define TYPEFLAG_PADDING 156
#define LINKNAME_PADDING 157
#define MAGIC_PADDING 257
#define VERSION_PADDING 263
#define UNAME_PADDING 265
#define GNAME_PADDING 297
#define DEVMAJOR_PADDING 329
#define DEVMINOR_PADDING 337
#define PREFIX_PADDING 345
#define PADDING_PADDING 500

struct tar_t
{                              /* byte offset, only the first 329bytes need to be checked */
    char name[100];               /*   0 */ // name of the file
    char mode[8];                 /* 100 */ // file mode, read/write/execute permissions for owner, group, others
    char uid[8];                  /* 108 */ // user id
    char gid[8];                  /* 116 */ // group id
    char size[12];                /* 124 */ // size of the file in bytes
    char mtime[12];               /* 136 */ // last modification time of the file
    char chksum[8];               /* 148 */ // checksum of the header
    char typeflag;                /* 156 */ // type of file, regular file, directory, link, etc
    char linkname[100];           /* 157 */ // if symlink, name of the file it points to
    char magic[6];                /* 257 */ // magic value, by default ustar
    char version[2];              /* 263 */ // version of the tar format
    char uname[32];               /* 265 */ // user name
    char gname[32];               /* 297 */ // group name
    char devmajor[8];             /* 329 */ // no need to fuzz this
    char devminor[8];             /* 337 */ // no need to fuzz this
    char prefix[155];             /* 345 */ // no need to fuzz this
    char padding[12];             /* 500 */ // no need to fuzz this
};

#endif //TAR_HEADER_H
