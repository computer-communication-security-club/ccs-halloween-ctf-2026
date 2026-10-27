/*
 * dsig_consts.h -- shared layout of the constant block embedded in the
 * DEAD SIGNAL binary.  The block begins with a 16-byte magic marker so the
 * organizer solver can locate and unpack it from the stripped ELF.
 *
 * NOTE: layout is part of the challenge contract.  solver.py unpacks it
 * with struct format "<16s24s24s24sIII6I6I6s2s24s128sI".
 */
#ifndef DSIG_CONSTS_H
#define DSIG_CONSTS_H

#include <stddef.h>
#include <stdint.h>

#define DSIG_TOKEN_LEN 24
#define DSIG_FLAG_MAX  128
#define DSIG_BLK_COUNT 6

typedef struct {
    char     magic[16];          /* "DSIGCONSTv1" + NUL padding            */
    uint8_t  perm[DSIG_TOKEN_LEN];
    uint8_t  xkey[DSIG_TOKEN_LEN];
    uint8_t  rots[DSIG_TOKEN_LEN];
    uint32_t roll_seed;
    uint32_t roll_mul;
    uint32_t roll_add;
    uint32_t blk_mul[DSIG_BLK_COUNT];
    uint32_t blk_add[DSIG_BLK_COUNT];
    uint8_t  blk_rol[DSIG_BLK_COUNT];
    uint8_t  reserved[2];
    uint8_t  target[DSIG_TOKEN_LEN];
    uint8_t  flag_ct[DSIG_FLAG_MAX];
    uint32_t flag_len;
} dsig_consts_t;

_Static_assert(sizeof(dsig_consts_t) == 312, "dsig_consts_t size");
_Static_assert(offsetof(dsig_consts_t, perm) == 16, "perm offset");
_Static_assert(offsetof(dsig_consts_t, xkey) == 40, "xkey offset");
_Static_assert(offsetof(dsig_consts_t, rots) == 64, "rots offset");
_Static_assert(offsetof(dsig_consts_t, roll_seed) == 88, "roll_seed offset");
_Static_assert(offsetof(dsig_consts_t, blk_mul) == 100, "blk_mul offset");
_Static_assert(offsetof(dsig_consts_t, blk_add) == 124, "blk_add offset");
_Static_assert(offsetof(dsig_consts_t, blk_rol) == 148, "blk_rol offset");
_Static_assert(offsetof(dsig_consts_t, target) == 156, "target offset");
_Static_assert(offsetof(dsig_consts_t, flag_ct) == 180, "flag_ct offset");
_Static_assert(offsetof(dsig_consts_t, flag_len) == 308, "flag_len offset");

#endif /* DSIG_CONSTS_H */
