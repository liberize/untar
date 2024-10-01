/*
 * Copyright (c) 2024 github.com/liberize/untar
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#pragma once
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>
#include <limits.h>
#include <time.h>

typedef enum tar_entry_type_e {
    // v7
    TAR_T_REGULAR1 = 0,
    TAR_T_REGULAR2 = '0',
    TAR_T_HARD = '1',
    TAR_T_SYMBOLIC = '2',
    // ustar
    TAR_T_CHARSPECIAL = '3',
    TAR_T_BLOCKSPECIAL = '4',
    TAR_T_DIRECTORY = '5',
    TAR_T_FIFO = '6',
    TAR_T_CONTIGUOUS = '7',
    // gnu
    TAR_T_LONGNAME = 'L',
    TAR_T_LONGLINK = 'K',
    // pax
    TAR_T_GLOBALEXTENDED = 'g',
    TAR_T_EXTENDED = 'x',
} tar_entry_type_t;

typedef struct tar_header_parsed_s {
    char *path;
    unsigned long long mode;
    unsigned long long uid;
    unsigned long long gid;
    unsigned long long size;
    double mtime;
    unsigned long long chksum;
    tar_entry_type_t typeflag;
    char *linkpath;

    char magic[8];
    char *uname;
    char *gname;
    unsigned long long devmajor;
    unsigned long long devminor;

    double atime;
    double ctime;

    // internal buffers
    char path_buf[257];
    char linkpath_buf[101];
    char uname_buf[33];
    char gname_buf[33];
} tar_header_parsed_t;

typedef struct tar_parse_cb_s {
    // user provided function to read data from tar archive
    int (*read) (unsigned char *buffer, int size, void *userdata);
    // user provided function to handle tar entry header, return non-zero value to abort
    int (*on_entry_header) (tar_header_parsed_t *entry, void *userdata);
    // user provided function to handle tar entry data chunk, may be called multiple times, return non-zero value to abort
    int (*on_entry_data) (tar_header_parsed_t *entry, const unsigned char *data, int size, void *userdata);
    // user provided function to handle tar entry ending, return non-zero value to abort
    int (*on_entry_end) (tar_header_parsed_t *entry, void *userdata);
    // user data that will be passed transparently to functions above
    void *userdata;
} tar_parse_cb_t;


static int untar(const char *filename);
static int untar_fd(int fd);
static int untar_fp(FILE *fp);
static int untar_mem(const unsigned char *data, size_t len);
static int untar_cb(tar_parse_cb_t cb);


// --- implementation ---

#include <sys/stat.h>
#include <fcntl.h>

#ifdef _WIN32
#include <windows.h>
#define PATH_MAX     MAX_PATH
#define strtoull     _strtoui64
#define snprintf     _snprintf
#define open         _open
#define fdopen       _fdopen
#define stat         _stat
#define lstat        _stat
#define unlink       _unlink
#define mkdir(d, m)  _mkdir(d)
#define chmod(...)
#define S_ISDIR(m)   (((m) & _S_IFMT) == _S_IFDIR)
#else
#include <sys/time.h>
#include <unistd.h>
#endif

#define LOGD(fmt, ...) fprintf(stdout, fmt "\n", ##__VA_ARGS__)
#define LOGE(fmt, ...) fprintf(stderr, fmt "\n", ##__VA_ARGS__)

#define TAR_BLOCK_SIZE 512

typedef struct tar_header_s {
    // v7 (pre-POSIX.1-1988)
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char chksum[8];
    char typeflag;      // or linkflag
    char linkname[100];

    // ustar (POSIX 1003.1)
    char magic[8];      // 6 bytes magic + 2 bytes version
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
    union {
        char prefix[155];
        // gnu
        struct {
            char atime[12];
            char ctime[12];
            // ...
        };
    };
} tar_header_t;

typedef struct pax_header_parsed_s {
    char has_uid;
    char has_gid;
    char has_size;
    char has_mtime;
    char has_atime;
    char has_ctime;

    char *path;
    unsigned long long uid;
    unsigned long long gid;
    unsigned long long size;
    double mtime;
    double atime;
    double ctime;
    char *linkpath;
    char *uname;
    char *gname;
    // ...
} pax_header_parsed_t;

typedef struct tar_context_s {
    int entry_index;
    int empty_count;
    tar_parse_cb_t cb;
    // gnu
    char *longname;
    int longname_wpos;
    char *longlink;
    int longlink_wpos;
    // pax
    char *pax_header;
    int pax_wpos;
    pax_header_parsed_t pax_parsed;
} tar_context_t;

typedef struct tar_default_userdata_s {
    FILE *fp_writer;
    FILE *fp_reader;
    const unsigned char *mem_ptr;
    size_t mem_size;
    size_t mem_rpos;
} tar_default_userdata_t;

static unsigned long long decode_number(char *buffer, int size) {
    unsigned long long r = 0;
    unsigned char *p = (unsigned char*)buffer;
    if ((p[0] & 0x80) != 0) {    // base256, gnu
        int negative = p[0] & 0x40;
        r = negative ? p[0] : (p[0] & 0x7f);
        for (int i = 1; i < size; i++) {
            r = (r << 8) | p[i];
        }
    } else {    // oct
        int i = 0;
        for (; i < size && buffer[i] == ' '; i++);
        for (; i < size && buffer[i] >= '0' && buffer[i] <= '7'; i++) {
            r = (r << 3) | (buffer[i] - '0');
        }
    }
    return r;
}

static int parse_header(tar_context_t *context, tar_header_t *raw, tar_header_parsed_t *parsed) {
    memset(parsed, 0, sizeof(tar_header_parsed_t));

    parsed->path = parsed->path_buf;
    parsed->linkpath = parsed->linkpath_buf;
    parsed->uname = parsed->uname_buf;
    parsed->gname = parsed->gname_buf;

    parsed->mode   = decode_number(raw->mode, sizeof(raw->mode));
    parsed->uid    = decode_number(raw->uid, sizeof(raw->uid));
    parsed->gid    = decode_number(raw->gid, sizeof(raw->gid));
    parsed->size   = decode_number(raw->size, sizeof(raw->size));
    parsed->mtime  = decode_number(raw->mtime, sizeof(raw->mtime));
    parsed->chksum = decode_number(raw->chksum, sizeof(raw->chksum));
    parsed->typeflag = raw->typeflag;
    strncpy(parsed->linkpath, raw->linkname, sizeof(raw->linkname));
    memcpy(parsed->magic, raw->magic, sizeof(raw->magic));
    
    strncpy(parsed->uname, raw->uname, sizeof(raw->uname));
    strncpy(parsed->gname, raw->gname, sizeof(raw->gname));
    parsed->devmajor = decode_number(raw->devmajor, sizeof(raw->devmajor));
    parsed->devminor = decode_number(raw->devminor, sizeof(raw->devminor));
    
    if (strcmp(parsed->magic, "ustar") == 0) {  // ustar
        strncpy(parsed->path, raw->prefix, sizeof(raw->prefix));
        if (parsed->path[0])
            strcat(parsed->path, "/");
    } else if (strcmp(parsed->magic, "ustar  ") == 0) {  // gnu
        parsed->atime = decode_number(raw->atime, sizeof(raw->atime));
        parsed->ctime = decode_number(raw->ctime, sizeof(raw->ctime));
    }
    strncat(parsed->path, raw->name, sizeof(raw->name));

    if (context->pax_header) {
        if (context->pax_parsed.path)
            parsed->path = context->pax_parsed.path;
        if (context->pax_parsed.linkpath)
            parsed->linkpath = context->pax_parsed.linkpath;
        if (context->pax_parsed.has_uid)
            parsed->uid = context->pax_parsed.uid;
        if (context->pax_parsed.has_gid)
            parsed->gid = context->pax_parsed.gid;
        if (context->pax_parsed.has_size)
            parsed->size = context->pax_parsed.size;
        if (context->pax_parsed.has_mtime)
            parsed->mtime = context->pax_parsed.mtime;
        if (context->pax_parsed.has_atime)
            parsed->atime = context->pax_parsed.atime;
        if (context->pax_parsed.has_ctime)
            parsed->ctime = context->pax_parsed.ctime;
        if (context->pax_parsed.uname)
            parsed->uname = context->pax_parsed.uname;
        if (context->pax_parsed.gname)
            parsed->gname = context->pax_parsed.gname;
    } else {
        if (context->longname)
            parsed->path = context->longname;
        if (context->longlink)
            parsed->linkpath = context->longlink;
    }

    return 0;
}

// https://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html#tag_20_92_13_03
// TODO: convert charset
static int parse_pax_header(tar_context_t *context) {
    char *line_beg = context->pax_header, *end = line_beg + context->pax_wpos;
    char *line_end, *p;
    while (line_beg < end) {
        unsigned long len = strtoul(line_beg, &p, 10);
        if (!len || *p != ' ')
            return -1;
        if (line_beg[len - 1] != '\n')
            return -2;
        line_beg[len - 1] = '\0';
        line_end = line_beg + len;
        char *key = ++p;
        while (p < line_end && *p != '=')
            ++p;
        if (p >= line_end)
            return -3;
        *p++ = '\0';
        LOGD("Found pax record. entry_index=%d key=%s val=%s", context->entry_index, key, p);
        if (strcmp(key, "path") == 0) {
            context->pax_parsed.path = p;
        } else if (strcmp(key, "linkpath") == 0) {
            context->pax_parsed.linkpath = p;
        } else if (strcmp(key, "size") == 0) {
            context->pax_parsed.size = strtoull(p, NULL, 10);
            context->pax_parsed.has_size = 1;
        } else if (strcmp(key, "uid") == 0) {
            context->pax_parsed.uid = strtoull(p, NULL, 10);
            context->pax_parsed.has_uid = 1;
        } else if (strcmp(key, "gid") == 0) {
            context->pax_parsed.gid = strtoull(p, NULL, 10);
            context->pax_parsed.has_gid = 1;
        } else if (strcmp(key, "mtime") == 0) {
            context->pax_parsed.mtime = strtod(p, NULL);
            context->pax_parsed.has_mtime = 1;
        } else if (strcmp(key, "atime") == 0) {
            context->pax_parsed.atime = strtod(p, NULL);
            context->pax_parsed.has_atime = 1;
        } else if (strcmp(key, "ctime") == 0) {
            context->pax_parsed.ctime = strtod(p, NULL);
            context->pax_parsed.has_ctime = 1;
        } else if (strcmp(key, "uname") == 0) {
            context->pax_parsed.uname= p;
        } else if (strcmp(key, "gname") == 0) {
            context->pax_parsed.gname = p;
        } else {
            LOGD("Ignore pax record. key=%s", key);
        }
        line_beg = line_end;
    }
    return 0;
}

static int read_block(tar_context_t *context, unsigned char *buffer) {
    if (!context->cb.read) {
        LOGE("Function pointer `read` not set!");
        return -1;
    }
    int num_read = context->cb.read(buffer, TAR_BLOCK_SIZE, context->cb.userdata);
    if (num_read < TAR_BLOCK_SIZE) {
        LOGE("Not enough data to read! num_read=%d", num_read);
        return -1;
    }
    return 0;
}

static void reset_overrides(tar_context_t *context) {
    free(context->longname);
    context->longname = NULL;
    context->longname_wpos = 0;

    free(context->longlink);
    context->longlink = NULL;
    context->longlink_wpos = 0;

    free(context->pax_header);
    context->pax_header = NULL;
    context->pax_wpos = 0;
    memset(&context->pax_parsed, 0, sizeof(context->pax_parsed));
}

static int handle_entry_header(tar_context_t *context, tar_header_parsed_t *entry) {
    LOGD("Found entry. index=%d type=%c path=%s size=%llu", context->entry_index, entry->typeflag, entry->path, entry->size);
    switch (entry->typeflag) {
        case TAR_T_LONGNAME:
            free(context->longname);
            context->longname_wpos = 0;
            context->longname = (char*) malloc(entry->size);
            if (!context->longname) {
                LOGE("Unable to alloc memory for long name! size=%llu", entry->size);
                return -1;
            }
            break;
        case TAR_T_LONGLINK:
            free(context->longlink);
            context->longlink_wpos = 0;
            context->longlink = (char*) malloc(entry->size);
            if (!context->longlink) {
                LOGE("Unable to alloc memory for long linkname! size=%llu", entry->size);
                return -1;
            }
            break;
        case TAR_T_GLOBALEXTENDED:
            break;      // ignore for now
        case TAR_T_EXTENDED:
            memset(&context->pax_parsed, 0, sizeof(context->pax_parsed));
            free(context->pax_header);
            context->pax_wpos = 0;
            context->pax_header = (char*) malloc(entry->size);
            if (!context->pax_header) {
                LOGE("Unable to alloc memory for pax header! size=%llu", entry->size);
                return -1;
            }
            break;
        default:
            if (context->cb.on_entry_header)
                if (context->cb.on_entry_header(entry, context->cb.userdata) != 0)
                    return -1;
            break;
    }
    return 0;
}

static int handle_entry_data(tar_context_t *context, tar_header_parsed_t *entry, unsigned char *block, int length) {
    switch (entry->typeflag) {
        case TAR_T_LONGNAME:
            memcpy(context->longname + context->longname_wpos, block, length);
            context->longname_wpos += length;
            break;
        case TAR_T_LONGLINK:
            memcpy(context->longlink + context->longlink_wpos, block, length);
            context->longlink_wpos += length;
            break;
        case TAR_T_GLOBALEXTENDED:
            break;
        case TAR_T_EXTENDED:
            memcpy(context->pax_header + context->pax_wpos, block, length);
            context->pax_wpos += length;
            break;
        default:
            if (context->cb.on_entry_data)
                if (context->cb.on_entry_data(entry, block, length, context->cb.userdata) != 0)
                    return -1;
            break;
    }
    return 0;
}

static int handle_entry_end(tar_context_t *context, tar_header_parsed_t *entry) {
    switch (entry->typeflag) {
        case TAR_T_LONGNAME:
        case TAR_T_LONGLINK:
            break;
        case TAR_T_GLOBALEXTENDED:
            break;      // ignore for now
        case TAR_T_EXTENDED: {
            int r = parse_pax_header(context);
            if (r != 0)
                LOGE("Failed to parse pax header! ret=%d", r);
            break;
        }
        default:
            if (context->cb.on_entry_end)
                if (context->cb.on_entry_end(entry, context->cb.userdata) != 0)
                    return -1;
            reset_overrides(context);
            break;
    }
    return 0;
}

static char *dir_name(const char *path, char *output) {
    int len = strlen(path);
    while (--len >= 0 && path[len] != '/');
    strncpy(output, path, ++len);
    output[len] = '\0';
    return output;
}

static int is_dir(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static int mkdir_recursive(char *dir, int mode) {
    if (!*dir)
        return 0;
    int ok = 1;
    char *p;
    for (p = dir + 1; ok && *p; p++)
        if (*p == '/') {
            *p = 0;
            ok = is_dir(dir) || mkdir(dir, mode) == 0;
            *p = '/';
        }
    if (ok && *--p != '/')
        ok = is_dir(dir) || mkdir(dir, mode) == 0;
    return ok ? 0 : -1;
}

#ifdef _WIN32
// target is relative to current dir, not to path of this entry (tested with gnu tar)
static int link(const char *target, const char *path) {
    return CreateHardLinkA(path, target, NULL) ? 0 : -1;
}

static int symlink(char *target, const char *path) {
    char target_full[PATH_MAX];
    strcat(dir_name(path, target_full), target);
    //FIXME: if target hasn't been extracted yet, flag may be wrong
    DWORD flags = (is_dir(target_full) ? SYMBOLIC_LINK_FLAG_DIRECTORY : 0) | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
    for (int i = 0; target[i]; i++)
        if (target[i] == '/')
            target[i] = '\\';
    return CreateSymbolicLinkA(path, target, flags) ? 0 : -1;  // need privileges
}

// windows has _utime, but it's usage is different from utimes and limited to 1 second precision
static int lutimes(const char *filename, const struct timeval tv[2]) {
    DWORD flags = is_dir(filename) ? FILE_FLAG_BACKUP_SEMANTICS : FILE_ATTRIBUTE_NORMAL;
    HANDLE hFile = CreateFile(filename, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, flags, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return -1;
    LONGLONG at = tv[0].tv_sec * 10000000LL + 116444736000000000LL + tv[0].tv_usec * 10LL;
    LONGLONG mt = tv[1].tv_sec * 10000000LL + 116444736000000000LL + tv[1].tv_usec * 10LL;
    FILETIME atime = { (DWORD) at, at >> 32 };
    FILETIME mtime = { (DWORD) mt, mt >> 32 };
    BOOL ok = SetFileTime(hFile, NULL, &atime, &mtime);
    CloseHandle(hFile);
    return ok ? 0 : -1;
}
#endif

static int default_on_entry_header(tar_header_parsed_t *entry, void *userdata) {
    tar_default_userdata_t *ud = (tar_default_userdata_t*) userdata;

    int pathlen = strlen(entry->path);
    if (pathlen-- > 1 && entry->path[pathlen] == '/') {
        entry->path[pathlen] = '\0';
        unlink(entry->path);
        entry->path[pathlen] = '/';
    } else
        unlink(entry->path);
    
    switch (entry->typeflag) {
        case TAR_T_REGULAR1:
        case TAR_T_REGULAR2:
        case TAR_T_CONTIGUOUS: {
            char dir[PATH_MAX];
            if (*dir_name(entry->path, dir)) {
                if (mkdir_recursive(dir, 0755) != 0) {
                    LOGE("Could not create directory for file. path=%s", entry->path);
                    return -1;
                }
            }
            if ((ud->fp_writer = fopen(entry->path, "wb")) == NULL) {
                LOGE("Could not open output file. path=%s", entry->path);
                return -1;
            }
            break;
        }
        case TAR_T_DIRECTORY:
            if (mkdir_recursive(entry->path, entry->mode) < 0) {
                LOGE("Unable to create directory. path=%s", entry->path);
                return -1;
            }
            break;
        case TAR_T_HARD:
            if (link(entry->linkpath, entry->path) < 0) {
                LOGE("Unable to create hardlink. path=%s target=%s", entry->path, entry->linkpath);
                return -1;
            }
            break;
        case TAR_T_SYMBOLIC:
            if (symlink(entry->linkpath, entry->path) < 0) {
                LOGE("Unable to create symlink. path=%s target=%s", entry->path, entry->linkpath);
                return -1;
            }
            break;
#ifndef _WIN32
        case TAR_T_CHARSPECIAL:
            if (mknod(entry->path, S_IFCHR | entry->mode, (entry->devmajor << 20) | entry->devminor) < 0) {
                LOGE("Unable to create char device. path=%s", entry->path);
                return -1;
            }
            break;
        case TAR_T_BLOCKSPECIAL:
            if (mknod(entry->path, S_IFBLK | entry->mode, (entry->devmajor << 20) | entry->devminor) < 0) {
                LOGE("Unable to create block device. path=%s", entry->path);
                return -1;
            }
            break;
        case TAR_T_FIFO:
            if (mkfifo(entry->path, entry->mode) < 0) {
                LOGE("Unable to create fifo. path=%s", entry->path);
                return -1;
            }
            break;
#endif
    }
    chmod(entry->path, entry->mode);
    return 0;
}

static int default_on_entry_data(tar_header_parsed_t *entry, const unsigned char *data, int size, void *userdata) {
    tar_default_userdata_t *ud = (tar_default_userdata_t*) userdata;
    if (ud->fp_writer != NULL)
        if (fwrite(data, 1, size, ud->fp_writer) != size)
            LOGE("Failed to write to output file!");
    return 0;
}

static int default_on_entry_end(tar_header_parsed_t *entry, void *userdata) {
    tar_default_userdata_t *ud = (tar_default_userdata_t*) userdata;
    if (ud->fp_writer != NULL) {
        fclose(ud->fp_writer);
        ud->fp_writer = NULL;
    }
    // FIXME: directory mtime should be set after all files in it have been extracted
    struct stat st;
    if (lstat(entry->path, &st) == 0) {
        struct timeval tvs[2];
        tvs[0].tv_sec = time(NULL);     // atime should be set to now, not atime in archive
        tvs[0].tv_usec = 0;
        tvs[1].tv_sec = (long) entry->mtime;
        tvs[1].tv_usec = (long) ((entry->mtime - tvs[1].tv_sec) * 1000000);
        if (lutimes(entry->path, tvs) < 0)
            LOGE("Unable to set mtime and atime. path=%s", entry->path);
    }
    return 0;
}

static int fp_read(unsigned char *buffer, int size, void *userdata) {
    tar_default_userdata_t *ud = (tar_default_userdata_t*) userdata;
    return fread(buffer, 1, size, ud->fp_reader);
}

static int mem_read(unsigned char *buffer, int size, void *userdata) {
    tar_default_userdata_t *ud = (tar_default_userdata_t*) userdata;
    if (size > ud->mem_size - ud->mem_rpos)
        size = ud->mem_size - ud->mem_rpos;
    memcpy(buffer, ud->mem_ptr + ud->mem_rpos, size);
    ud->mem_rpos += size;
    return size;
}

static int untar(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        LOGE("Failed to open file for reading!");
        return -1;
    }
    int r = untar_fp(fp);
    fclose(fp);
    return r;
}

static int untar_fd(int fd) {
    FILE *fp = fdopen(fd, "rb");
    if (fp == NULL) {
        LOGE("Failed to open fd for reading!");
        return -1;
    }
    int r = untar_fp(fp);
    fclose(fp);
    return r;
}

static int untar_fp(FILE *fp) {
    tar_default_userdata_t ud;
    memset(&ud, 0, sizeof(ud));
    ud.fp_reader = fp;

    tar_parse_cb_t cb;
    cb.read = fp_read;
    cb.on_entry_header = default_on_entry_header;
    cb.on_entry_data = default_on_entry_data;
    cb.on_entry_end = default_on_entry_end;
    cb.userdata = &ud;
    return untar_cb(cb);
}

static int untar_mem(const unsigned char *data, size_t len) {
    tar_default_userdata_t ud;
    memset(&ud, 0, sizeof(ud));
    ud.mem_ptr = data;
    ud.mem_size = len;

    tar_parse_cb_t cb;
    cb.read = mem_read;
    cb.on_entry_header = default_on_entry_header;
    cb.on_entry_data = default_on_entry_data;
    cb.on_entry_end = default_on_entry_end;
    cb.userdata = &ud;
    return untar_cb(cb);
}

static int untar_cb(tar_parse_cb_t cb) {
    int i, remain_size, current_size;
    unsigned char buffer[TAR_BLOCK_SIZE + 1];
    tar_header_parsed_t header_parsed;
    tar_context_t context;
    memset(&context, 0, sizeof(context));
    context.cb = cb;
    
    while (context.empty_count < 2) {

        if (read_block(&context, buffer) != 0)
            break;

        for (i = 0; i < TAR_BLOCK_SIZE && !buffer[i]; i++);
        if (i >= TAR_BLOCK_SIZE) {
            context.empty_count++;
            context.entry_index++;
            continue;
        }
        context.empty_count = 0;
        
        if (parse_header(&context, (tar_header_t*) buffer, &header_parsed) != 0)
            break;

        if (handle_entry_header(&context, &header_parsed) != 0)
            break;
    
        remain_size = header_parsed.size;
        while (remain_size > 0) {
            if (read_block(&context, buffer) != 0)
                break;

            current_size = remain_size < TAR_BLOCK_SIZE ? remain_size : TAR_BLOCK_SIZE;
            buffer[current_size] = 0;

            if (handle_entry_data(&context, &header_parsed, buffer, current_size) != 0)
                break;
            
            remain_size -= current_size;
        }

        handle_entry_end(&context, &header_parsed);

        if (remain_size > 0)
            break;

        context.entry_index++;
    }

    reset_overrides(&context);
    return context.empty_count < 2 ? -1 : 0;
}
