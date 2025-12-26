#pragma once
#include <memory>

namespace gloo {

struct Context {
  int rank;
  int size;

  Context(int r, int s) : rank(r), size(s) {}
};

}