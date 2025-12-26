
#include "mp_context.h"

#include <stdexcept>

namespace gloo {
namespace transport {
namespace mp {

MpContext::MpContext(int rank, int size)
    : rank_(rank), size_(size), conns_(size) {}

std::shared_ptr<MpContext> MpContext::create(
    const std::shared_ptr<::gloo::Context>& ctx,
    const std::shared_ptr<rendezvous::Store>& store) {
  if (!ctx) {
    throw std::invalid_argument("MpContext::create: ctx is null");
  }
  if (!store) {
    throw std::invalid_argument("MpContext::create: store is null");
  }

  auto mpCtx = std::make_shared<MpContext>(ctx->rank, ctx->size);

  // For each root/sender, set up a connection
  for (int root = 0; root < mpCtx->size_; ++root) {
    mpCtx->initConnectionForRoot(root, store);
  }

  return mpCtx;
}

const MpConnection& MpContext::connectionForRoot(int root) const {
  if (root < 0 || root >= size_) {
    throw std::out_of_range("MpContext::connectionForRoot: invalid root");
  }
  return conns_[root];
}

MpConnection& MpContext::connectionForRoot(int root) {
  if (root < 0 || root >= size_) {
    throw std::out_of_range("MpContext::connectionForRoot: invalid root");
  }
  return conns_[root];
}


void MpContext::initConnectionForRoot(
    int root,
    const std::shared_ptr<rendezvous::Store>& store) {
  MpConnection conn;
  conn.root = root;
  conn.isSender = (rank_ == root);

  const std::string key = "mp_endpoint_root_" + std::to_string(root);

  if (conn.isSender) {
    // Root should listen first then update connection info. mp_listen should be non-blocked.
    MpHandle h = mp_listen();
    MpEndpoint ep = mp_local_endpoint(h);
    std::string epStr = serializeEndpoint(ep);

    store->set(key, epStr);

    conn.handle = new MpHandle(std::move(h));
  } else {
    // Block until read info
    std::string epStr = store->get(key); 
    MpEndpoint ep = parseEndpoint(epStr);
    MpHandle h = mp_connect(ep);

    conn.handle = new MpHandle(std::move(h));
  }

  conns_[root] = std::move(conn);
}

} // namespace mp
} // namespace transport
} // namespace gloo
