//
// Created by alex on 2/03/24.
//

#ifndef TAR_HEADER_H
#define TAR_HEADER_H

struct tar_t
{                              /* byte offset, only the first 329bytes need to be checked */
    char name[100];               /*   0 */
    char mode[8];                 /* 100 */
    char uid[8];                  /* 108 */
    char gid[8];                  /* 116 */
    char size[12];                /* 124 */
    char mtime[12];               /* 136 */
    char chksum[8];               /* 148 */
    char typeflag;                /* 156 */
    char linkname[100];           /* 157 */
    char magic[6];                /* 257 */
    char version[2];              /* 263 */
    char uname[32];               /* 265 */
    char gname[32];               /* 297 */
    char devmajor[8];             /* 329 */ // no need to fuzz this
    char devminor[8];             /* 337 */ // no need to fuzz this
    char prefix[155];             /* 345 */ // no need to fuzz this
    char padding[12];             /* 500 */ // no need to fuzz this
};

#endif //TAR_HEADER_H
