# untar

Single file untar library, support the following tar formats:

* v7 (Pre-POSIX.1-1988)
* ustar (POSIX IEEE P1003.1)
* gnu (GNU tar >= 1.13.12)
* oldgnu (GNU tar <= 1.12)
* pax (POSIX.1-2001)

## Usage

Just `#include "untar.h"`, then use one of the following untar functions:

```c

// extract from file to disk
int untar(const char *filename);
// extract from file descriptor to disk
int untar_fd(int fd);
// extract from FILE pointer to disk
int untar_fp(FILE *fp);
// extract from mem data to disk
int untar_mem(const unsigned char *data, size_t len);

// extract with custom callbacks, checkout untar_fp/untar_mem source code for examples
int untar_cb(tar_parse_cb_t cb);
```
