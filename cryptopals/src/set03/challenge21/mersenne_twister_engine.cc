#include <random>

class CMersenneTwister19937 {
  std::mt19937 mt;

public:
  CMersenneTwister19937() : mt() {}
  CMersenneTwister19937(uint32_t seed) : mt(seed) {}
  ~CMersenneTwister19937() {}
  uint32_t generate() { return mt(); }
};

extern "C" void *cstd_mt19937_default() {
  CMersenneTwister19937 *mt = new CMersenneTwister19937();
  return static_cast<void *>(mt);
}

extern "C" void *cstd_mt19937_create(uint32_t seed) {
  CMersenneTwister19937 *mt = new CMersenneTwister19937(seed);
  return static_cast<void *>(mt);
}

extern "C" void cstd_mt19937_release(void *mtp) {
  CMersenneTwister19937 *mt = static_cast<CMersenneTwister19937 *>(mtp);
  delete mt;
}

extern "C" uint32_t cstd_mt19937_generate(void *mtp) {
  CMersenneTwister19937 *mt = static_cast<CMersenneTwister19937 *>(mtp);
  return mt->generate();
}

class CMersenneTwister19937_64 {
  std::mt19937_64 mt;

public:
  CMersenneTwister19937_64() : mt() {}
  CMersenneTwister19937_64(uint64_t seed) : mt(seed) {}
  ~CMersenneTwister19937_64() {}
  uint64_t generate() { return mt(); }
};

extern "C" void *cstd_mt19937_64_default() {
  CMersenneTwister19937_64 *mt = new CMersenneTwister19937_64();
  return static_cast<void *>(mt);
}

extern "C" void *cstd_mt19937_64_create(uint64_t seed) {
  CMersenneTwister19937_64 *mt = new CMersenneTwister19937_64(seed);
  return static_cast<void *>(mt);
}

extern "C" void cstd_mt19937_64_release(void *mtp) {
  CMersenneTwister19937_64 *mt = static_cast<CMersenneTwister19937_64 *>(mtp);
  delete mt;
}

extern "C" uint64_t cstd_mt19937_64_generate(void *mtp) {
  CMersenneTwister19937_64 *mt = static_cast<CMersenneTwister19937_64 *>(mtp);
  return mt->generate();
}
