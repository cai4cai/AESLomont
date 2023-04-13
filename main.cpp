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

// code to test the algorithm
#include "AES.h"
#include "Rijndael.h"
#ifdef _WIN32
#include <windows.h>
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <fstream>
#include <iostream>

// define this to test old direct slow method, else remove for fast method
// #define USE_SLOW_RIJNDAEL
#define RANDOM_TEST_COUNT 1000  // how many random tests to do

#ifdef USE_SLOW_RIJNDAEL
#define AES Rijndael
#endif

typedef struct {
  const char* key;
  const char* plaintext;
  const char* ciphertext;
  const char* e_vectors[9];
  const char* d_vectors[9];
} test_t;

// todo - add all checks from the NIST document in the header comment

test_t vectors[] = {
    // a test vector from NIST
    {"000102030405060708090A0B0C0D0E0F",   // key
     "000102030405060708090A0B0C0D0E0F",   // plaintext
     "0A940BB5416EF045F1C39458C653EA5A",   // ciphertext
     {"B5C9179EB1CC1199B9C51B92B5C8159D",  // encryption vectors
      "2B65F6374C427C5B2FE3A9256896755B", "D1015FCBB4EF65679688462076B9D6AD",
      "8E17064A2A35A183729FE59FF3A591F1", "D7557DD55999DB3259E2183D558DCDD2",
      "73A96A5D7799A5F3111D2B63684B1F7F", "1B6B853069EEFC749AFEFD7B57A04CD1",
      "107EEADFB6F77933B5457A6F08F046B2", "8EC166481A677AA96A14FF6ECE88C010"},

     {"8EC166481A677AA96A14FF6ECE88C010",  // decryption vectors
      "107EEADFB6F77933B5457A6F08F046B2", "1B6B853069EEFC749AFEFD7B57A04CD1",
      "73A96A5D7799A5F3111D2B63684B1F7F", "D7557DD55999DB3259E2183D558DCDD2",
      "8E17064A2A35A183729FE59FF3A591F1", "D1015FCBB4EF65679688462076B9D6AD",
      "2B65F6374C427C5B2FE3A9256896755B", "B5C9179EB1CC1199B9C51B92B5C8159D"}},

    // a bunch of different test values
    {"00010203050607080A0B0C0D0F101112",
     "506812A45F08C889B97F5980038B8359",
     "D8F532538289EF7D06B506A4FD5BE9C9",
     {0},
     {0}},

    {"00010203050607080A0B0C0D0F10111214151617191A1B1C",
     "2D33EEF2C0430A8A9EBF45E809C40BB6",
     "DFF4945E0336DF4C1C56BC700EFF837F",
     {0},
     {0}},

    {"50515253555657585A5B5C5D5F60616264656667696A6B6C6E6F707173747576",
     "050407067477767956575051221D1C1F",
     "7444527095838FE080FC2BCDD30847EB",
     {0},
     {0}},

    {"000000000000000000000000000000000200000000000000",
     "00000000000000000000000000000000",
     "5D989E122B78C758921EDBEEB827F0C0",
     {0},
     {0}},
};

void TextToHex(const char* in, char* data) {
  // given a text string, convert to hex data
  int val;
  while (*in) {
    val = *in++;
    if (val > '9')
      val = toupper(val) - 'A' + 10;
    else
      val = val - '0';
    *data = val * 16;
    val = *in++;
    if (val > '9')
      val = toupper(val) - 'A' + 10;
    else
      val = val - '0';
    *data++ += val;
  }
}  // TextToHex

// test a given test vector, see that internals are working
// return false iff fails
bool TestVector(const test_t& vector, bool use_states) {
  bool retval = true;  // assume passes
  // data sizes in bytes
  int keylen = strlen(vector.key) / 2, blocklen = strlen(vector.plaintext) / 2;

  AES crypt;
  crypt.SetParameters(keylen * 8, blocklen * 8);
  unsigned char key[32], plaintext[32], ciphertext[32], temptext[32];
  unsigned char states[4096 * 20];

  TextToHex(vector.key, reinterpret_cast<char*>(key));
  TextToHex(vector.ciphertext, reinterpret_cast<char*>(ciphertext));
  TextToHex(vector.plaintext, reinterpret_cast<char*>(plaintext));

  if (use_states == true) {
    for (int pos = 0; pos < 9; pos++) {
      TextToHex(vector.e_vectors[pos],
                reinterpret_cast<char*>(states) + pos * 16);
    }
  }

  crypt.StartEncryption(key);
#ifdef USE_SLOW_RIJNDAEL
  if (use_states == true) {
    crypt.EncryptBlock(plaintext, temptext, states);
  } else {
    crypt.EncryptBlock(plaintext, temptext);
  }
#else
  crypt.EncryptBlock(plaintext, temptext);
#endif

  // check that temp = cipher
  if (memcmp(ciphertext, temptext, blocklen) != 0) {
    std::cout << "Error: encryption error\n";
    retval = false;
  } else {
    std::cout << "Encryption passed\n";
  }

  crypt.StartDecryption(key);
#ifdef USE_SLOW_RIJNDAEL
  if (use_states == true) {
    crypt.DecryptBlock(ciphertext, temptext, states);
  } else {
    crypt.DecryptBlock(ciphertext, temptext);
  }
#else
  crypt.DecryptBlock(ciphertext, temptext);
#endif

  if (memcmp(plaintext, temptext, blocklen) != 0) {
    std::cout << "Error: decryption error\n";
    retval = false;
  } else {
    std::cout << "Decryption passed\n";
  }

  return retval;
}  // TestVector

// return false iff 2 byte end values not preserved
bool CheckBuffer(const unsigned char* buf, int length) {
  return (0xBE == buf[0]) && (0xEF == buf[1]) && (0xBE == buf[length + 2]) &&
         (0xEF == buf[length + 3]);
}  // CheckBuffer

// return false iff fails
bool RandomTest(int pos) {
  // data sizes in bytes
  int keylen, blocklen, datalen, mode;
  keylen = (std::rand() % 3) * 8 + 16;
  blocklen = (std::rand() % 3) * 8 + 16;
  mode = std::rand() % 2;  // various chaining modes
  assert((16 == keylen) || (24 == keylen) || (32 == keylen));
  assert((16 == blocklen) || (24 == blocklen) || (32 == blocklen));

#define MAXDATA 4096  // max length of random data
  AES crypt;
  crypt.SetParameters(keylen * 8, blocklen * 8);
  datalen = std::rand() % MAXDATA;
  unsigned char key[32], plaintext[MAXDATA + 40], ciphertext[MAXDATA + 40],
      temptext[MAXDATA + 40];

  std::cout << "Test: " << pos + 1 << "  (keysize,blocksize,datalength): ("
            << keylen << ',' << blocklen << "," << datalen << ")\n";

  for (pos = 0; pos < keylen; pos++) key[pos] = std::rand();
  // add buffer bytes to each end to catch errors
  plaintext[0] = 0xBE;
  plaintext[1] = 0xEF;
  ciphertext[0] = 0xBE;
  ciphertext[1] = 0xEF;
  temptext[0] = 0xBE;
  temptext[1] = 0xEF;
  for (pos = 0; pos < datalen; pos++) plaintext[pos + 2] = std::rand();
  // pad
  int padlen = blocklen - (datalen % blocklen);
  for (pos = 0; pos < padlen; pos++) plaintext[pos + 2 + datalen] = 0;
  // add buffer bytes to each end to catch errors
  pos = padlen + 2 + datalen;
  plaintext[pos] = 0xBE;
  plaintext[pos + 1] = 0xEF;
  ciphertext[pos] = 0xBE;
  ciphertext[pos + 1] = 0xEF;
  temptext[pos] = 0xBE;
  temptext[pos + 1] = 0xEF;

#undef MAXDATA

  int blocks = (datalen + blocklen - 1) / blocklen;
  crypt.StartEncryption(key);
  crypt.Encrypt(plaintext + 2, ciphertext + 2, blocks,
                static_cast<AES::BlockMode>(mode));

  crypt.StartDecryption(key);
  crypt.Decrypt(ciphertext + 2, temptext + 2, blocks,
                static_cast<AES::BlockMode>(mode));

  if (memcmp(plaintext + 2, temptext + 2, datalen) != 0) {
    std::cout << "Error: decryption error\n";
    return false;
  } else if ((false == CheckBuffer(plaintext, datalen + padlen)) ||
             (false == CheckBuffer(temptext, datalen + padlen)) ||
             (false == CheckBuffer(ciphertext, datalen + padlen))) {
    std::cout << "Error: buffer overflow\n";
    return false;
  } else {
    std::cout << "Decryption passed\n";
  }
  return true;
}  // RandomTest

void Timing(int rounds, int keylen, int blocklen) {
  unsigned char key[32], plaintext[32], ciphertext[32];

  int pos;

  AES crypt;
  crypt.SetParameters(keylen * 8, blocklen * 8);

  std::srand(0);  // make repeatable
  for (pos = 0; pos < keylen; pos++) {
    key[pos] = std::rand();
  }
  for (pos = 0; pos < blocklen; pos++) {
    plaintext[pos] = std::rand();
  }

  // Find Timing overhead for these
  // TODO(unknown) get more precise counters
  auto start1 = std::chrono::steady_clock::now();
  auto end1 = std::chrono::steady_clock::now();
  std::chrono::duration<double> overhead = end1 - start1;

  crypt.StartEncryption(key);
  int64_t min_e = 1000000;
  double total_e = 0;
  for (pos = 0; pos < rounds; pos++) {
    start1 = std::chrono::steady_clock::now();
    crypt.EncryptBlock(plaintext, ciphertext);
    end1 = std::chrono::steady_clock::now();
    std::chrono::duration<double> timediff = end1 - start1;
    const double amortised_timediff =
        std::chrono::duration_cast<std::chrono::microseconds>(timediff -
                                                              overhead)
            .count();
    total_e += amortised_timediff;
    if (min_e > amortised_timediff) {
      min_e = amortised_timediff;
    }
  }

  std::cout << "Min microsecs per encryption (key,block): (" << keylen * 8
            << ',' << blocklen * 8 << ") ";
  std::cout << min_e << std::endl;

  std::cout << "Avg microsecs per encryption (key,block): (" << keylen * 8
            << ',' << blocklen * 8 << ") ";
  std::cout << total_e / rounds << std::endl;

  crypt.StartDecryption(key);
  int64_t min_d = 1000000;
  double total_d = 0;

  for (pos = 0; pos < rounds; pos++) {
    start1 = std::chrono::steady_clock::now();
    crypt.DecryptBlock(plaintext, ciphertext);
    end1 = std::chrono::steady_clock::now();
    std::chrono::duration<double> timediff = end1 - start1;
    const double amortised_timediff =
        std::chrono::duration_cast<std::chrono::microseconds>(timediff -
                                                              overhead)
            .count();
    total_d += amortised_timediff;
    if (min_d > amortised_timediff) {
      min_d = amortised_timediff;
    }
  }

  std::cout << "Min microsecs per decryption (key,block): (" << keylen * 8
            << ',' << blocklen * 8 << ") " << min_d << std::endl;
  std::cout << "Avg microsecs per decryption (key,block): (" << keylen * 8
            << ',' << blocklen * 8 << ") " << total_d / rounds << std::endl;
}  // Timing

// test a file encryption
void AESEncryptFile(const char* fname) {
  std::ifstream ifile(fname, std::ios_base::binary);
  std::ofstream ofile("aesout.dat", std::ios_base::binary);

  // get file size
  ifile.seekg(0, std::ios_base::end);
  int size, fsize = ifile.tellg();
  ifile.seekg(0, std::ios_base::beg);

  // round up (ignore pad for here)
  size = (fsize + 15) & (~15);

  char* ibuffer = new char[size];
  char* obuffer = new char[size];
  ifile.read(ibuffer, fsize);

  AES crypt;
  crypt.SetParameters(192);
  // random key good enough
  unsigned char key[192 / 8];
  for (size_t pos = 0; pos < sizeof(key); ++pos) key[pos] = std::rand();
  crypt.StartEncryption(key);
  crypt.Encrypt(reinterpret_cast<const unsigned char*>(ibuffer),
                reinterpret_cast<unsigned char*>(obuffer), size / 16);

  ofile.write(obuffer, size);

  delete[] ibuffer;
  delete[] obuffer;

  ofile.close();
  ifile.close();
}  // AESEncryptFile

int main(void) {
#ifdef USE_SLOW_RIJNDAEL
  std::cout << "Running slow Rijndael test" << std::endl;
#else
  std::cout << "Running AES test" << std::endl;
#endif

#ifdef _WIN32
  // to try to prevent windows from interfering too much
  SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
  SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
#endif

  bool allPassed = true;  // asusme this

  // some test vectors to check integrity
  allPassed &= TestVector(vectors[0], true);
  allPassed &= TestVector(vectors[1], false);
  allPassed &= TestVector(vectors[2], false);
  allPassed &= TestVector(vectors[3], false);
  allPassed &= TestVector(vectors[4], false);

  // check a bunch of timings for different key and block sizes
  for (int block = 16; block <= 32; block += 8) {
    for (int key = 16; key <= 32; key += 8) {
      Timing(100000, key, block);
    }
  }

  // this is to randomly test data
  srand(0);  // make reproducible
  std::cout << "Random tests:\n";
  for (int pos = 0; pos < RANDOM_TEST_COUNT; pos++) {
    bool passed = RandomTest(pos);
    allPassed &= passed;
    if (passed == false) std::cerr << "Random Test " << pos << " failed\n";
  }

  if (false == allPassed)
    std::cerr << "ERROR: Some test(s) failed\n";
  else
    std::cout << "PASSED: All tests passed\n";

  // test a file encryption
  // AESEncryptFile("main.cpp");

  return 0;
}  // main

// end - main.cpp
