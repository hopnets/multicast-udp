#pragma once
#include <condition_variable>
#include <mutex>
#include <string>
#include <unordered_map>

namespace gloo {

class Store {
 public:
  void set(const std::string& key, const std::string& value) {
    {
      std::lock_guard<std::mutex> lock(mu_);
      map_[key] = value;
    }
    cv_.notify_all();
  }

  std::string get(const std::string& key) {
    std::unique_lock<std::mutex> lock(mu_);
    cv_.wait(lock, [&] { return map_.count(key) > 0; });
    return map_[key];
  }

 private:
    std::mutex mu_;
    std::condition_variable cv_;
    std::unordered_map<std::string, std::string> map_;
};

}