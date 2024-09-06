
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <errno.h>


/* The callback functions take a buffer, a length, and an opaque */
/* pointer which is passed through. They MUST return zero (0) on */
/* success. Any non-zero value is treated as an error and bubbled*/
/* back up to the caller. Note that "short" reads and writes   */
/* are NOT used or supported in this interface, unlike that of   */
/* read(2)/write(2).                                             */



// https://github.com/DiUS/cser/blob/master/test.c
typedef int (*cser_raw_write_fn) (const uint8_t *bytes, size_t n, void *q);
typedef int (*cser_raw_read_fn) (uint8_t *bytes, size_t n, void *q);