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
// extract to disk
int untar(const char *filename);
int untar_fd(int fd);
int untar_fp(FILE *fp);
int untar_mem(const unsigned char *data, size_t len);

// extract with callbacks, checkout untar_fp/untar_mem source code for examples
int untar_cb(tar_parse_cb_t cb);
```
