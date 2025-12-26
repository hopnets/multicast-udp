// mp_context.h
#pragma once

#include <string>
#include <vector>

#include "context.h"
#include "store.h"

namespace gloo {
namespace transport {
namespace mp {


struct MpHandle;    // Multicast protocol handler. Should be a struct or a fd
struct MpEndpoint;  // Connection info


MpHandle mp_listen();
MpHandle mp_connect(const MpEndpoint&);

MpEndpoint mp_local_endpoint(const MpHandle&);
std::string serializeEndpoint(const MpEndpoint& ep);
MpEndpoint parseEndpoint(const std::string&);


struct MpConnection {
  int root = -1;
  bool isSender = false;
  MpHandle* handle = nullptr;
};

class MpContext {
 public:
  MpContext(int rank, int size);

  MpContext(const MpContext&) = delete;
  MpContext& operator=(const MpContext&) = delete;

  int rank() const {
    return rank_;
  }

  int size() const {
    return size_;
  }

  const MpConnection& connectionForRoot(int root) const;
  MpConnection& connectionForRoot(int root);

  static std::shared_ptr<MpContext> create(
      const std::shared_ptr<gloo::Context>& ctx,
      const std::shared_ptr<gloo::Store>& store);

 private:
  int rank_;
  int size_;
  std::vector<MpConnection> conns_;

  void initConnectionForRoot(int root,
                             const std::shared_ptr<gloo::Store>& store);
};

} // namespace mp
} // namespace transport
} // namespace gloo
