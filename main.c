#include "untar.h"

int main(int argc, char **argv) {
    if (argc != 2) {
        LOGE("Usage: %s *.tar", argv[0]);
        return 0;
    }
    return untar(argv[1]);
}
