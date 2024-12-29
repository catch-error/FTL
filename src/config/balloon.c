/* balloon.c

   Balloon password-hashing algorithm.

   Copyright (C) 2022 Zoltan Fridrich
   Copyright (C) 2022 Red Hat, Inc.

   This file is part of GNU Nettle.

   GNU Nettle is free software: you can redistribute it and/or
   modify it under the terms of either:

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at your
       option) any later version.

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at your
       option) any later version.

   or both in parallel, as here.

   GNU Nettle is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see http://www.gnu.org/licenses/.
*/

/* For a description of the algorithm, see:
 * Boneh, D., Corrigan-Gibbs, H., Schechter, S. (2017, May 12). Balloon Hashing:
 * A Memory-Hard Function Providing Provable Protection Against Sequential Attacks.
 * Retrieved Sep 1, 2022, from https://eprint.iacr.org/2016/027.pdf
 */

#include <string.h>

#include <nettle/macros.h>
#include <nettle/nettle-types.h>
#include <nettle/sha2.h>

#define DELTA 3

static void
hash(void *ctx,
     nettle_hash_update_func *update,
     nettle_hash_digest_func *digest,
     size_t digest_size,
     uint64_t cnt,
     size_t a_len, const uint8_t *a,
     size_t b_len, const uint8_t *b,
     uint8_t *dst)
{
  uint8_t tmp[8];
  LE_WRITE_UINT64(tmp, cnt);
  update(ctx, sizeof(tmp), tmp);
  if (a && a_len)
    update(ctx, a_len, a);
  if (b && b_len)
    update(ctx, b_len, b);
  digest(ctx, digest_size, dst);
}

static void
hash_ints(void *ctx,
          nettle_hash_update_func *update,
          nettle_hash_digest_func *digest,
          size_t digest_size,
          uint64_t i, uint64_t j, uint64_t k,
          uint8_t *dst)
{
  uint8_t tmp[24];
  LE_WRITE_UINT64(tmp, i);
  LE_WRITE_UINT64(tmp + 8, j);
  LE_WRITE_UINT64(tmp + 16, k);
  update(ctx, sizeof(tmp), tmp);
  digest(ctx, digest_size, dst);
}

/* Takes length bytes long big number stored
 * in little endian format and computes modulus
 */
static size_t
block_to_int(size_t length, const uint8_t *block, size_t mod)
{
  size_t i = length, r = 0;
  while (i--)
    {
      r = (r << 8) + block[i];
      r %= mod;
    }
  return r;
}

static void
balloon(void *hash_ctx,
        nettle_hash_update_func *update,
        nettle_hash_digest_func *digest,
        size_t digest_size, size_t s_cost, size_t t_cost,
        size_t passwd_length, const uint8_t *passwd,
        size_t salt_length, const uint8_t *salt,
        uint8_t *scratch, uint8_t *dst)
{
  const size_t BS = digest_size;
  uint8_t *block = scratch;
  uint8_t *buf = scratch + BS;
  size_t i, j, k, cnt = 0;

  hash(hash_ctx, update, digest, digest_size,
       cnt++, passwd_length, passwd, salt_length, salt, buf);
  for (i = 1; i < s_cost; ++i)
    hash(hash_ctx, update, digest, digest_size,
         cnt++, BS, buf + (i - 1) * BS, 0, NULL, buf + i * BS);

  for (i = 0; i < t_cost; ++i)
    {
      for (j = 0; j < s_cost; ++j)
        {
          hash(hash_ctx, update, digest, digest_size,
               cnt++, BS, buf + (j ? j - 1 : s_cost - 1) * BS,
               BS, buf + j * BS, buf + j * BS);
          for (k = 0; k < DELTA; ++k)
            {
              hash_ints(hash_ctx, update, digest, digest_size, i, j, k, block);
              hash(hash_ctx, update, digest, digest_size,
                   cnt++, salt_length, salt, BS, block, block);
              hash(hash_ctx, update, digest, digest_size,
                   cnt++, BS, buf + j * BS,
                   BS, buf + block_to_int(BS, block, s_cost) * BS,
                   buf + j * BS);
            }
        }
    }
  memcpy(dst, buf + (s_cost - 1) * BS, BS);
}

static void
balloon_sha256(size_t s_cost, size_t t_cost,
               size_t passwd_length, const uint8_t *passwd,
               size_t salt_length, const uint8_t *salt,
               uint8_t *scratch, uint8_t *dst)
{
  struct sha256_ctx ctx;
  sha256_init(&ctx);
  balloon(&ctx,
          (nettle_hash_update_func*)sha256_update,
          (nettle_hash_digest_func*)sha256_digest,
          SHA256_DIGEST_SIZE, s_cost, t_cost,
          passwd_length, passwd, salt_length, salt, scratch, dst);
}

static size_t
balloon_itch(size_t digest_size, size_t s_cost)
{
  return (s_cost + 1) * digest_size;
}
