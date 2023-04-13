/* AES - Advanced Encryption Standard

  source version 1.0, June, 2005

  Copyright (C) 2000-2005 Chris Lomont

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the author be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

  Chris Lomont
  chris@lomont.org

  The AES Standard is maintained by NIST
  http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf

  This legalese is patterned after the zlib compression library
*/

// code to implement Advanced Encryption Standard - Rijndael
// direct, slow method
#include "Rijndael.h"

#include <cassert>
#include <cstdio>

#include <fstream>
#include <iostream>

// internally data is stored in the state in order
//   0  1  2  3
//   4  5  6  7
//   8  8 10 11
//   ...
// up to Nb of these
// NOTE: thus rows and columns are interchanged from the paper

namespace {  // anonymous namespace

// have the tables been initialized?
bool tablesInitialized = false;

// constants defining the algorithm
int const gf2_8_poly = 0x11B;  // the poly defining the 256 element field
// poly defining mixing, coeffs usually '03010102'
// const uint32_t poly32 = 0x03010102;
// poly inverse, coeffs usually '0B0D090E'
// const uint32_t poly32_inv = 0x0B0D090E;

int const parameters[] = {
    // data in  Nr,C1,C2,C3 form
    // Nk*32 128         192         256
    10, 1, 2, 3, 12, 1, 2, 3, 14, 1, 2, 3,  // Nb*32 = 128
    12, 1, 2, 3, 12, 1, 2, 3, 14, 1, 2, 3,  // Nb*32 = 192
    14, 1, 3, 4, 14, 1, 3, 4, 14, 1, 3, 4,  // Nb*32 = 256
};

// tables for inverses, byte sub
unsigned char gf2_8_inv[256] = {
    0x00, 0x01, 0x8d, 0xf6, 0xcb, 0x52, 0x7b, 0xd1, 0xe8, 0x4f, 0x29, 0xc0,
    0xb0, 0xe1, 0xe5, 0xc7, 0x74, 0xb4, 0xaa, 0x4b, 0x99, 0x2b, 0x60, 0x5f,
    0x58, 0x3f, 0xfd, 0xcc, 0xff, 0x40, 0xee, 0xb2, 0x3a, 0x6e, 0x5a, 0xf1,
    0x55, 0x4d, 0xa8, 0xc9, 0xc1, 0x0a, 0x98, 0x15, 0x30, 0x44, 0xa2, 0xc2,
    0x2c, 0x45, 0x92, 0x6c, 0xf3, 0x39, 0x66, 0x42, 0xf2, 0x35, 0x20, 0x6f,
    0x77, 0xbb, 0x59, 0x19, 0x1d, 0xfe, 0x37, 0x67, 0x2d, 0x31, 0xf5, 0x69,
    0xa7, 0x64, 0xab, 0x13, 0x54, 0x25, 0xe9, 0x09, 0xed, 0x5c, 0x05, 0xca,
    0x4c, 0x24, 0x87, 0xbf, 0x18, 0x3e, 0x22, 0xf0, 0x51, 0xec, 0x61, 0x17,
    0x16, 0x5e, 0xaf, 0xd3, 0x49, 0xa6, 0x36, 0x43, 0xf4, 0x47, 0x91, 0xdf,
    0x33, 0x93, 0x21, 0x3b, 0x79, 0xb7, 0x97, 0x85, 0x10, 0xb5, 0xba, 0x3c,
    0xb6, 0x70, 0xd0, 0x06, 0xa1, 0xfa, 0x81, 0x82, 0x83, 0x7e, 0x7f, 0x80,
    0x96, 0x73, 0xbe, 0x56, 0x9b, 0x9e, 0x95, 0xd9, 0xf7, 0x02, 0xb9, 0xa4,
    0xde, 0x6a, 0x32, 0x6d, 0xd8, 0x8a, 0x84, 0x72, 0x2a, 0x14, 0x9f, 0x88,
    0xf9, 0xdc, 0x89, 0x9a, 0xfb, 0x7c, 0x2e, 0xc3, 0x8f, 0xb8, 0x65, 0x48,
    0x26, 0xc8, 0x12, 0x4a, 0xce, 0xe7, 0xd2, 0x62, 0x0c, 0xe0, 0x1f, 0xef,
    0x11, 0x75, 0x78, 0x71, 0xa5, 0x8e, 0x76, 0x3d, 0xbd, 0xbc, 0x86, 0x57,
    0x0b, 0x28, 0x2f, 0xa3, 0xda, 0xd4, 0xe4, 0x0f, 0xa9, 0x27, 0x53, 0x04,
    0x1b, 0xfc, 0xac, 0xe6, 0x7a, 0x07, 0xae, 0x63, 0xc5, 0xdb, 0xe2, 0xea,
    0x94, 0x8b, 0xc4, 0xd5, 0x9d, 0xf8, 0x90, 0x6b, 0xb1, 0x0d, 0xd6, 0xeb,
    0xc6, 0x0e, 0xcf, 0xad, 0x08, 0x4e, 0xd7, 0xe3, 0x5d, 0x50, 0x1e, 0xb3,
    0x5b, 0x23, 0x38, 0x34, 0x68, 0x46, 0x03, 0x8c, 0xdd, 0x9c, 0x7d, 0xa0,
    0xcd, 0x1a, 0x41, 0x1c,
};

unsigned char byte_sub[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16,
};

unsigned char inv_byte_sub[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d,
};

// this table needs Nb*(Nr+1)/Nk entries - up to 8*(15)/4 = 60
uint32_t Rcon[60] = {
    // todo -  this table may be stored as bytes or made on the fly
    0x00000000, 0x00000001, 0x00000002, 0x00000004, 0x00000008, 0x00000010,
    0x00000020, 0x00000040, 0x00000080, 0x0000001b, 0x00000036, 0x0000006c,
    0x000000d8, 0x000000ab, 0x0000004d, 0x0000009a, 0x0000002f, 0x0000005e,
    0x000000bc, 0x00000063, 0x000000c6, 0x00000097, 0x00000035, 0x0000006a,
    0x000000d4, 0x000000b3, 0x0000007d, 0x000000fa, 0x000000ef, 0x000000c5,
    0x00000091, 0x00000039, 0x00000072, 0x000000e4, 0x000000d3, 0x000000bd,
    0x00000061, 0x000000c2, 0x0000009f, 0x00000025, 0x0000004a, 0x00000094,
    0x00000033, 0x00000066, 0x000000cc, 0x00000083, 0x0000001d, 0x0000003a,
    0x00000074, 0x000000e8, 0x000000cb, 0x0000008d, 0x00000001, 0x00000002,
    0x00000004, 0x00000008, 0x00000010, 0x00000020, 0x00000040, 0x0000001b,
};

// mult 2 elements using gf2_8_poly as a reduction
unsigned char GF2_8_mult(
    unsigned char a,
    unsigned char b) {  // todo - make 4x4 table for nibbles, use lookup
  unsigned char result = 0;

  // should give 0x57 . 0x13 = 0xFE with poly 0x11B
  //

  int count = 8;
  while (count--) {
    if (b & 1) result ^= a;
    if (a & 128) {
      a <<= 1;
      a ^= (gf2_8_poly & 255);
    } else {
      a <<= 1;
    }
    b >>= 1;
  }
  return result;
}  // GF2_8_mult

// some functions to create/verify table integrity
bool CheckInverses(bool create) {
  // we'll brute force the inverse table
  assert(GF2_8_mult(0x57, 0x13) == 0xFE);  // test these first
  assert(GF2_8_mult(0x01, 0x01) == 0x01);
  assert(GF2_8_mult(0xFF, 0x55) == 0xF8);

  unsigned int a, b;  // need int here to prevent wraps in loop
  if (create == true)
    const_cast<unsigned char *>(gf2_8_inv)[0] = 0;
  else if (gf2_8_inv[0] != 0)
    return false;
  for (a = 1; a <= 255; a++) {
    b = 1;
    while (GF2_8_mult(a, b) != 1) b++;

    if (create == true)
      const_cast<unsigned char *>(gf2_8_inv)[a] = b;
    else if (gf2_8_inv[a] != b)
      return false;
  }
  return true;
}  // CheckInverses

unsigned char BitSum(unsigned char byte) {  // return the sum of bits mod 2
  byte = (byte >> 4) ^ (byte & 15);
  byte = (byte >> 2) ^ (byte & 3);
  return (byte >> 1) ^ (byte & 1);
}  // BitSum

bool CheckByteSub(bool create) {
  if (CheckInverses(create) == false)
    return false;  // we cannot do this without inverses

  unsigned int x, y;  // need ints here to prevent wrap in loop
  for (x = 0; x <= 255; x++) {
    y = gf2_8_inv[x];  // inverse to start with

    // affine transform
    y = BitSum(y & 0xF1) | (BitSum(y & 0xE3) << 1) | (BitSum(y & 0xC7) << 2) |
        (BitSum(y & 0x8F) << 3) | (BitSum(y & 0x1F) << 4) |
        (BitSum(y & 0x3E) << 5) | (BitSum(y & 0x7C) << 6) |
        (BitSum(y & 0xF8) << 7);
    y = y ^ 0x63;
    if (create == true)
      const_cast<unsigned char *>(byte_sub)[x] = y;
    else if (byte_sub[x] != y)
      return false;
  }
  return true;
}  // CheckByteSub

bool CheckInvByteSub(bool create) {
  if (CheckInverses(create) == false)
    return false;  // we cannot do this without inverses
  if (CheckByteSub(create) == false)
    return false;  // we cannot do this without byte_sub

  unsigned int x, y;  // need ints here to prevent wrap in loop
  for (x = 0; x <= 255; x++) {
    // we brute force it...
    y = 0;
    while (byte_sub[y] != x) y++;
    if (create == true)
      const_cast<unsigned char *>(inv_byte_sub)[x] = y;
    else if (inv_byte_sub[x] != y)
      return false;
  }
  return true;
}  // CheckInvByteSub

bool CheckRcon(bool create) {
  unsigned char Ri = 1;  // start here

  if (create == true)
    Rcon[0] = 0;
  else if (Rcon[0] != 0)
    return false;  // todo - this is unused still check?
  for (unsigned int i = 1; i < sizeof(Rcon) / sizeof(Rcon[0]) - 1; i++) {
    if (create == true)
      Rcon[i] = Ri;
    else if (Rcon[i] != Ri)
      return false;
    Ri = GF2_8_mult(Ri, 0x02);  // multiply by x - todo replace with xmult
  }
  return true;
}  // CheckRCon
}  // namespace

// the transforms
void Rijndael::ByteSub(void) {
  for (int pos = 0; pos < state_size; pos++) state[pos] = byte_sub[state[pos]];
}  // ByteSub

void Rijndael::InvByteSub(void) {
  unsigned char *s = state;
  for (int pos = 0; pos < state_size; pos++) *s = inv_byte_sub[*s++];
}  // InvByteSub

void Rijndael::ShiftRow(void) {
  unsigned char arr[10];
  int i, j;

  // copy out row, then copy back 2 pieces shifted
  for (j = 0, i = 1; j < Nb; i += 4, j++) arr[j] = state[i];
  for (j = C1, i = 1; j < Nb; i += 4, j++) state[i] = arr[j];
  for (j = 0, i = 1 + 4 * (Nb - C1); j < C1; i += 4, j++) state[i] = arr[j];

  for (j = 0, i = 2; j < Nb; i += 4, j++) arr[j] = state[i];
  for (j = C2, i = 2; j < Nb; i += 4, j++) state[i] = arr[j];
  for (j = 0, i = 2 + 4 * (Nb - C2); j < C2; i += 4, j++) state[i] = arr[j];

  for (j = 0, i = 3; j < Nb; i += 4, j++) arr[j] = state[i];
  for (j = C3, i = 3; j < Nb; i += 4, j++) state[i] = arr[j];
  for (j = 0, i = 3 + 4 * (Nb - C3); j < C3; i += 4, j++) state[i] = arr[j];
}  // ShiftRow

void Rijndael::InvShiftRow(void) {
  unsigned char arr[10];
  int i, j;

  for (j = 0, i = 1; j < Nb; i += 4, j++) arr[j] = state[i];
  for (j = Nb - C1, i = 1; j < Nb; i += 4, j++) state[i] = arr[j];
  for (j = 0, i = 1 + 4 * C1; j < Nb - C1; i += 4, j++) state[i] = arr[j];

  for (j = 0, i = 2; j < Nb; i += 4, j++) arr[j] = state[i];
  for (j = Nb - C2, i = 2; j < Nb; i += 4, j++) state[i] = arr[j];
  for (j = 0, i = 2 + 4 * C2; j < Nb - C2; i += 4, j++) state[i] = arr[j];

  for (j = 0, i = 3; j < Nb; i += 4, j++) arr[j] = state[i];
  for (j = Nb - C3, i = 3; j < Nb; i += 4, j++) state[i] = arr[j];
  for (j = 0, i = 3 + 4 * C3; j < Nb - C3; i += 4, j++) state[i] = arr[j];
}  // InvShiftRow

#define xmult(a) ((a) << 1) ^ (((a)&128) ? 0x01B : 0)

void Rijndael::MixColumn(
    void) {  // poly32 used here - we hard coded - todo - use defines
  unsigned char a0, a1, a2, a3, b0, b1, b2, b3;
  for (int col = 0; col < Nb; col++) {
    a0 = state[col * 4 + 0];
    a1 = state[col * 4 + 1];
    a2 = state[col * 4 + 2];
    a3 = state[col * 4 + 3];

    // todo - this could be sped up with a 2 = xmult function, and 3 =
    // xmult(a)^a
    b0 = xmult(a0) ^ a1 ^ xmult(a1) ^ a2 ^ a3;
    b1 = a0 ^ xmult(a1) ^ a2 ^ xmult(a2) ^ a3;
    b2 = a0 ^ a1 ^ xmult(a2) ^ a3 ^ xmult(a3);
    b3 = a0 ^ xmult(a0) ^ a1 ^ a2 ^ xmult(a3);

    state[col * 4 + 0] = b0;
    state[col * 4 + 1] = b1;
    state[col * 4 + 2] = b2;
    state[col * 4 + 3] = b3;
  }
}  // MixColumn

void Rijndael::InvMixColumn(
    void) {  // poly32_inv used here - we hard coded - todo - defines
  unsigned char a0, a1, a2, a3, b0, b1, b2, b3;
  for (int col = 0; col < Nb; col++) {
    a0 = state[4 * col + 0];
    a1 = state[4 * col + 1];
    a2 = state[4 * col + 2];
    a3 = state[4 * col + 3];

    b0 = GF2_8_mult(0x0E, a0) ^ GF2_8_mult(0x0B, a1) ^ GF2_8_mult(0x0D, a2) ^
         GF2_8_mult(0x09, a3);
    b1 = GF2_8_mult(0x09, a0) ^ GF2_8_mult(0x0E, a1) ^ GF2_8_mult(0x0B, a2) ^
         GF2_8_mult(0x0D, a3);
    b2 = GF2_8_mult(0x0D, a0) ^ GF2_8_mult(0x09, a1) ^ GF2_8_mult(0x0E, a2) ^
         GF2_8_mult(0x0B, a3);
    b3 = GF2_8_mult(0x0B, a0) ^ GF2_8_mult(0x0D, a1) ^ GF2_8_mult(0x09, a2) ^
         GF2_8_mult(0x0E, a3);

    state[4 * col + 0] = b0;
    state[4 * col + 1] = b1;
    state[4 * col + 2] = b2;
    state[4 * col + 3] = b3;
  }
}  // InvMixColumn

void Rijndael::AddRoundKey(int round) {
  const unsigned char *r_ptr = W + round * state_size;
  unsigned char *s_ptr = state;

  for (int pos = 0; pos < state_size; pos++) {
    *s_ptr++ ^= *r_ptr++;
  }
}  // AddRoundKey

// the round functions
void Rijndael::Round(int round) {
  ByteSub();
  ShiftRow();
  MixColumn();
  AddRoundKey(round);
}  // Round

void Rijndael::InvRound(int round) {
  AddRoundKey(round);
  InvMixColumn();
  InvShiftRow();
  InvByteSub();
}  // InvRound

void Rijndael::FinalRound(int round) {
  ByteSub();
  ShiftRow();
  AddRoundKey(round);
}  // FinalRound

void Rijndael::InvFinalRound(int round) {
  AddRoundKey(round);
  InvShiftRow();
  InvByteSub();
}  // FinalRound

uint32_t Rijndael::RotByte(uint32_t data) {
  // bytes (a,b,c,d) -> (b,c,d,a) so low becomes high
  return (data << 24) | (data >> 8);
  // todo inline with rotr
}  // RotByte

uint32_t Rijndael::SubByte(uint32_t data) {
  // does the SBox on this 4 byte data
  uint32_t result = 0;
  result = byte_sub[data >> 24];
  result <<= 8;
  result |= byte_sub[(data >> 16) & 255];
  result <<= 8;
  result |= byte_sub[(data >> 8) & 255];
  result <<= 8;
  result |= byte_sub[data & 255];
  return result;
}  // SubByte

// Key expansion code - makes local copy
void Rijndael::KeyExpansion(const unsigned char *key) {
  assert(Nk > 0);
  int i;
  // todo not portable - Endian problems
  uint32_t temp, *Wb = reinterpret_cast<uint32_t *>(W);
  if (Nk <= 6) {
    // todo - memcpy
    for (i = 0; i < 4 * Nk; i++) W[i] = key[i];
    for (i = Nk; i < Nb * (Nr + 1); i++) {
      temp = Wb[i - 1];
      if ((i % Nk) == 0) {
        temp = SubByte(RotByte(temp)) ^ Rcon[i / Nk];
      }
      Wb[i] = Wb[i - Nk] ^ temp;
    }
  } else {
    // todo - memcpy
    for (i = 0; i < 4 * Nk; i++) W[i] = key[i];
    for (i = Nk; i < Nb * (Nr + 1); i++) {
      temp = Wb[i - 1];
      if ((i % Nk) == 0) {
        temp = SubByte(RotByte(temp)) ^ Rcon[i / Nk];
      } else if ((i % Nk) == 4) {
        temp = SubByte(temp);
      }
      Wb[i] = Wb[i - Nk] ^ temp;
    }
  }
}  // KeyExpansion

void Rijndael::SetParameters(int keylength, int blocklength) {
  Nk = Nr = Nb = 0;  // default values

  if ((keylength != 128) && (keylength != 192) && (keylength != 256))
    return;  // nothing - todo - throw error?
  if ((blocklength != 128) && (blocklength != 192) && (blocklength != 256))
    return;  // nothing - todo - throw error?

  // legal parameters, so fire it up
  Nk = keylength / 32;
  Nb = blocklength / 32;

  state_size = 4 * Nb;  // bytes in state vector

  // fill memory
  Nr = parameters[((Nk - 4) / 2 + 3 * (Nb - 4) / 2) * 4 + 0];
  C1 = parameters[((Nk - 4) / 2 + 3 * (Nb - 4) / 2) * 4 + 1];
  C2 = parameters[((Nk - 4) / 2 + 3 * (Nb - 4) / 2) * 4 + 2];
  C3 = parameters[((Nk - 4) / 2 + 3 * (Nb - 4) / 2) * 4 + 3];
}  // SetParameters

void DumpCharTable(std::ostream &out, const char *name,
                   const unsigned char *table,
                   int length) {  // dump te contents of a table to a file
  int pos;
  out << name << std::endl << std::hex;
  for (pos = 0; pos < length; pos++) {
    out << "0x";
    if (table[pos] < 16) {
      out << '0';
    }
    out << static_cast<unsigned int>(table[pos]) << ',';
    if ((pos % 16) == 15) {
      out << std::endl;
    }
  }
  out << std::dec;
}  // DumpCharTable

void DumpLongTable(std::ostream &out, const char *name, const uint32_t *table,
                   int length) {  // dump te contents of a table to a file
  int pos;
  out << name << std::endl << std::hex;
  for (pos = 0; pos < length; pos++) {
    out << "0x";
    if (table[pos] < 16) {
      out << '0';
    }
    if (table[pos] < 16 * 16) {
      out << '0';
    }
    if (table[pos] < 16 * 16 * 16) {
      out << '0';
    }
    if (table[pos] < 16 * 16 * 16 * 16) {
      out << '0';
    }
    if (table[pos] < 16 * 16 * 16 * 16 * 16) {
      out << '0';
    }
    if (table[pos] < 16 * 16 * 16 * 16 * 16 * 16) {
      out << '0';
    }
    if (table[pos] < 16 * 16 * 16 * 16 * 16 * 16 * 16) {
      out << '0';
    }
    out << static_cast<unsigned int>(table[pos]) << ',';
    if ((pos % 8) == 7) {
      out << std::endl;
    }
  }
  out << std::dec;
}  // DumpCharTable

// return true iff tables are valid. create = true fills them in if not
bool CreateRijndaelTables(bool create, bool create_file) {
  bool retval = true;
  if (CheckInverses(create) == false) {
    retval = false;
  }
  if (CheckByteSub(create) == false) {
    retval = false;
  }
  if (CheckInvByteSub(create) == false) {
    retval = false;
  }
  if (CheckRcon(create) == false) {
    return false;
  }

  if (create_file == true) {  // dump tables
    std::ofstream out;
    out.open("Tables.dat");
    if (out.is_open() == true) {
      DumpCharTable(out, "gf2_8_inv", gf2_8_inv, 256);
      out << "\n\n";
      DumpCharTable(out, "byte_sub", byte_sub, 256);
      out << "\n\n";
      DumpCharTable(out, "inv_byte_sub", inv_byte_sub, 256);
      out << "\n\n";
      DumpLongTable(out, "RCon", Rcon, 60);
      out.close();
    }
  }
  return retval;
}  // CreateRijndaelTables

void Rijndael::StartEncryption(const unsigned char *key) {
  KeyExpansion(key);
}  // StartEncryption

void DumpHex(const unsigned char *table,
             int length) {  // dump some hex values for debugging
  int pos;
  std::cerr << std::hex;
  for (pos = 0; pos < length; pos++) {
    if (table[pos] < 16) {
      std::cerr << '0';
    }
    std::cerr << static_cast<unsigned int>(table[pos]) << ' ';
    if ((pos % 16) == 15) {
      std::cerr << std::endl;
    }
  }
  std::cerr << std::dec;
}  // DumpHex

void Rijndael::EncryptBlock(
    const unsigned char *datain1, unsigned char *dataout1,
    const unsigned char *states) {  // todo ? allow in place encryption
  const uint32_t *datain = reinterpret_cast<const uint32_t *>(datain1);
  uint32_t *dataout = reinterpret_cast<uint32_t *>(dataout1);

  memcpy(state, datain, state_size);
  AddRoundKey(0);
  for (int i = 1; i < Nr; i++) {
    Round(i);
    if (0 != states) {  // compare
      if (memcmp(state, states + (i - 1) * state_size, state_size) != 0) {
        std::cerr << "State " << i << " failed:\n";
        std::cerr << "State     : ";
        DumpHex(state, state_size);
        std::cerr << "Should be : ";
        DumpHex(states + (i - 1) * state_size, state_size);
      }
    }
  }
  FinalRound(Nr);
  memcpy(dataout, state, state_size);
}  // Encrypt

// call this to encrypt any size block
void Rijndael::Encrypt(const unsigned char *datain, unsigned char *dataout,
                       uint32_t numBlocks, BlockMode mode) {
  if (0 == numBlocks) return;
  unsigned int blocksize = Nb * 4;
  switch (mode) {
    case ECB:
      while (numBlocks) {
        EncryptBlock(datain, dataout);
        datain += blocksize;
        dataout += blocksize;
        --numBlocks;
      }
      break;
    case CBC: {
      unsigned char buffer[64];
      memset(buffer, 0,
             sizeof(buffer));  // clear out - todo - allow setting the
                               // Initialization Vector - needed for security
      while (numBlocks) {
        for (unsigned int pos = 0; pos < blocksize; ++pos)
          buffer[pos] ^= *datain++;
        EncryptBlock(buffer, dataout);
        memcpy(buffer, dataout, blocksize);
        dataout += blocksize;
        --numBlocks;
      }
    } break;
    default:
      assert(!"Unknown mode!");
      break;
  }
}  // Encrypt

void Rijndael::StartDecryption(const unsigned char *key) {
  KeyExpansion(key);
}  // StartDecryption

void Rijndael::DecryptBlock(const unsigned char *datain1,
                            unsigned char *dataout1,
                            const unsigned char *states) {
  const uint32_t *datain = reinterpret_cast<const uint32_t *>(datain1);
  uint32_t *dataout = reinterpret_cast<uint32_t *>(dataout1);

  memcpy(state, datain, state_size);
  InvFinalRound(Nr);
  for (int i = Nr - 1; i > 0; i--) {
    if (0 != states) {  // compare
      if (memcmp(state, states + (i - 1) * state_size, state_size) != 0) {
        std::cerr << "State " << i << " failed:\n";
        std::cerr << "State     : ";
        DumpHex(state, state_size);
        std::cerr << "Should be : ";
        DumpHex(states + (i - 1) * state_size, state_size);
      }
    }
    InvRound(i);
  }
  AddRoundKey(0);
  memcpy(dataout, state, state_size);
}  // Decrypt

// call this to decrypt any size block
void Rijndael::Decrypt(const unsigned char *datain, unsigned char *dataout,
                       uint32_t numBlocks, BlockMode mode) {
  if (0 == numBlocks) return;
  unsigned int blocksize = Nb * 4;
  switch (mode) {
    case ECB:
      while (numBlocks) {
        DecryptBlock(datain, dataout);
        datain += blocksize;
        dataout += blocksize;
        --numBlocks;
      }
      break;
    case CBC: {
      unsigned char buffer[64];
      memset(buffer, 0,
             sizeof(buffer));  // clear out - todo - allow setting the
                               // Initialization Vector - needed for security
      DecryptBlock(datain, dataout);  // do first block
      for (unsigned int pos = 0; pos < blocksize; ++pos)
        *dataout++ ^= buffer[pos];
      datain += blocksize;
      numBlocks--;

      while (numBlocks) {
        DecryptBlock(datain, dataout);  // do first block
        for (unsigned int pos = 0; pos < blocksize; ++pos)
          *dataout++ ^= *(datain - blocksize + pos);
        datain += blocksize;
        --numBlocks;
      }
    } break;
    default:
      assert(!"Unknown mode!");
  }
}  // Decrypt

// the constructor - makes sure local things are initialized
Rijndael::Rijndael(void) {
  if (false == tablesInitialized)
    tablesInitialized = CreateRijndaelTables(true, false);
  if (false == tablesInitialized) throw "Tables failed to initialize";
}

// end - Rijndael.cpp
