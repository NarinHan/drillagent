#include <algorithm>
#include <chrono>
#include <cstdint>
#include <deque>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>
#include <cstring>

// Roughly ~300 lines demo C++17 program
// Build: g++ -std=c++17 demo.cpp -O2 -Wall -Wextra

namespace demo {

// -------------------------
// Small logging helpers
// -------------------------
enum class Level { Info, Warn, Error };

static inline const char* levelName(Level lv) {
  switch (lv) {
    case Level::Info:  return "INFO";
    case Level::Warn:  return "WARN";
    case Level::Error: return "ERROR";
    default:           return "UNKNOWN";
  }
}

template <class... Args>
void log(Level lv, Args&&... args) {
  std::cout << "[" << levelName(lv) << "] ";
  (std::cout << ... << std::forward<Args>(args));
  std::cout << "\n";
}

// -------------------------
// Utilities
// -------------------------
static inline uint64_t nowMs() {
  using namespace std::chrono;
  return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

static inline std::string trim(std::string s) {
  auto isSpace = [](unsigned char c) { return std::isspace(c); };
  while (!s.empty() && isSpace(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
  while (!s.empty() && isSpace(static_cast<unsigned char>(s.back())))  s.pop_back();
  return s;
}

static inline std::vector<std::string> split(std::string_view sv, char delim) {
  std::vector<std::string> out;
  std::string cur;
  for (char c : sv) {
    if (c == delim) {
      out.push_back(cur);
      cur.clear();
    } else {
      cur.push_back(c);
    }
  }
  out.push_back(cur);
  return out;
}

// -------------------------
// Variant-based Event model
// -------------------------
struct EAdd { int x; };
struct EMul { int x; };
struct EReset {};
struct EMsg { std::string msg; };

using Event = std::variant<EAdd, EMul, EReset, EMsg>;

static inline std::string eventToString(const Event& e) {
  return std::visit([](auto&& ev) -> std::string {
    using T = std::decay_t<decltype(ev)>;
    if constexpr (std::is_same_v<T, EAdd>)   return "EAdd(" + std::to_string(ev.x) + ")";
    if constexpr (std::is_same_v<T, EMul>)   return "EMul(" + std::to_string(ev.x) + ")";
    if constexpr (std::is_same_v<T, EReset>) return "EReset()";
    if constexpr (std::is_same_v<T, EMsg>)   return "EMsg('" + ev.msg + "')";
    return "Unknown";
  }, e);
}

// -------------------------
// Template: ring buffer
// -------------------------
template <class T>
class RingBuffer {
 public:
  explicit RingBuffer(size_t cap) : cap_(cap) {}

  void push(T v) {
    if (cap_ == 0) return;
    if (buf_.size() == cap_) {
      buf_.pop_front();
    }
    buf_.push_back(std::move(v));
  }

  const std::deque<T>& data() const { return buf_; }

 private:
  size_t cap_;
  std::deque<T> buf_;
};

// -------------------------
// A tiny “engine” interface
// -------------------------
class Engine {
 public:
  virtual ~Engine() = default;
  virtual void onEvent(const Event& e) = 0;
  virtual int value() const = 0;
  virtual std::string name() const = 0;
};

class AccumulatorEngine : public Engine {
 public:
  explicit AccumulatorEngine(int seed = 0) : v_(seed) {}

  void onEvent(const Event& e) override {
    std::visit([this](auto&& ev) {
      using T = std::decay_t<decltype(ev)>;
      if constexpr (std::is_same_v<T, EAdd>) {
        v_ += ev.x;
      } else if constexpr (std::is_same_v<T, EMul>) {
        v_ *= ev.x;
      } else if constexpr (std::is_same_v<T, EReset>) {
        v_ = 0;
      } else if constexpr (std::is_same_v<T, EMsg>) {
        // just ignore
        (void)ev;
      }
    }, e);
  }

  int value() const override { return v_; }
  std::string name() const override { return "AccumulatorEngine"; }

 private:
  int v_;
};

class CappedEngine : public Engine {
 public:
  CappedEngine(std::unique_ptr<Engine> inner, int cap)
      : inner_(std::move(inner)), cap_(cap) {}

  void onEvent(const Event& e) override {
    inner_->onEvent(e);
    if (inner_->value() > cap_) overflow_ = true;
  }

  int value() const override {
    return std::min(inner_->value(), cap_);
  }

  std::string name() const override {
    return "Capped(" + inner_->name() + ", cap=" + std::to_string(cap_) + ")";
  }

  bool overflowed() const { return overflow_; }

 private:
  std::unique_ptr<Engine> inner_;
  int cap_;
  bool overflow_ = false;
};

// -------------------------
// “Parser” for commands
// -------------------------
static inline std::optional<Event> parseLine(std::string line) {
  line = trim(std::move(line));
  if (line.empty()) return std::nullopt;

  auto parts = split(line, ' ');
  auto cmd = parts[0];

  auto parseInt = [&](size_t idx) -> std::optional<int> {
    if (idx >= parts.size()) return std::nullopt;
    try {
      return std::stoi(parts[idx]);
    } catch (...) {
      return std::nullopt;
    }
  };

  if (cmd == "add") {
    auto x = parseInt(1);
    if (!x) return std::nullopt;
    return Event{EAdd{*x}};
  }
  if (cmd == "mul") {
    auto x = parseInt(1);
    if (!x) return std::nullopt;
    return Event{EMul{*x}};
  }
  if (cmd == "reset") {
    return Event{EReset{}};
  }
  if (cmd == "msg") {
    // msg <text...>
    std::ostringstream oss;
    for (size_t i = 1; i < parts.size(); i++) {
      if (i > 1) oss << " ";
      oss << parts[i];
    }
    return Event{EMsg{oss.str()}};
  }
  return std::nullopt;
}

// -------------------------
// “Bad smell” function for ast-grep demo
// -------------------------
// Intentionally uses C-style buffer & strncpy in a risky way.
// (If src length >= dstSize, result may be non-null-terminated.)
static inline std::string unsafeCopyToFixed(const std::string& src) {
  constexpr size_t dstSize = 16; // magic number on purpose
  char buf[dstSize];
  std::strncpy(buf, src.c_str(), dstSize); // risky demo
  // buf[dstSize - 1] = '\0'; // intentionally commented out
  return std::string(buf); // undefined-ish read if not terminated
}

// -------------------------
// Metrics collector
// -------------------------
struct Metrics {
  uint64_t startMs = nowMs();
  size_t events = 0;
  std::map<std::string, size_t> byType;

  void add(const Event& e) {
    events++;
    byType[eventToString(e).substr(0, 4)]++; // "EAdd", "EMul", ...
  }

  void dump() const {
    auto dur = nowMs() - startMs;
    log(Level::Info, "Runtime=", dur, "ms, events=", events);
    for (const auto& [k, v] : byType) {
      log(Level::Info, "  ", k, ": ", v);
    }
  }
};

// -------------------------
// Scenario runner
// -------------------------
class Runner {
 public:
  explicit Runner(std::unique_ptr<Engine> eng)
      : eng_(std::move(eng)), history_(64) {}

  void feed(const Event& e) {
    metrics_.add(e);
    history_.push(eventToString(e));
    eng_->onEvent(e);
  }

  void runScript(const std::vector<std::string>& lines) {
    for (const auto& line : lines) {
      auto ev = parseLine(line);
      if (!ev) {
        log(Level::Warn, "skip invalid line: '", line, "'");
        continue;
      }
      log(Level::Info, "event: ", eventToString(*ev));
      feed(*ev);
      if (eng_->value() == 0) {
        // small branch to make patterns interesting
        log(Level::Info, "value hit zero");
      }
    }
  }

  void summary() const {
    log(Level::Info, "Engine: ", eng_->name());
    log(Level::Info, "Value: ", eng_->value());
    log(Level::Info, "History(last ", history_.data().size(), "):");
    for (const auto& s : history_.data()) {
      std::cout << "  - " << s << "\n";
    }
    metrics_.dump();
  }

 private:
  std::unique_ptr<Engine> eng_;
  RingBuffer<std::string> history_;
  Metrics metrics_;
};

// -------------------------
// Random script generator
// -------------------------
static inline std::vector<std::string> makeRandomScript(int n, uint32_t seed) {
  std::mt19937 rng(seed);
  std::uniform_int_distribution<int> op(0, 3);
  std::uniform_int_distribution<int> val(1, 5);

  std::vector<std::string> lines;
  lines.reserve(static_cast<size_t>(n));

  for (int i = 0; i < n; i++) {
    int o = op(rng);
    if (o == 0) lines.push_back("add " + std::to_string(val(rng)));
    else if (o == 1) lines.push_back("mul " + std::to_string(val(rng)));
    else if (o == 2) lines.push_back("reset");
    else lines.push_back("msg hello_" + std::to_string(i));
  }
  return lines;
}

// -------------------------
// Main
// -------------------------
} // namespace demo

int main(int argc, char** argv) {
  using namespace demo;

  log(Level::Info, "demo started");

  int seedValue = 1;
  int cap = 100;

  if (argc >= 2) {
    try { seedValue = std::stoi(argv[1]); }
    catch (...) { log(Level::Warn, "bad seed arg, use default"); }
  }
  if (argc >= 3) {
    try { cap = std::stoi(argv[2]); }
    catch (...) { log(Level::Warn, "bad cap arg, use default"); }
  }

  auto base = std::make_unique<AccumulatorEngine>(seedValue);
  auto capped = std::make_unique<CappedEngine>(std::move(base), cap);
  Runner runner(std::move(capped));

  // deterministic script
  std::vector<std::string> script = {
      "add 3",
      "mul 2",
      "msg hello world",
      "add 7",
      "reset",
      "mul 9",          // will keep 0
      "add 5",
      "bogus 123",      // invalid
      "msg done"
  };

  runner.runScript(script);

  // random script
  auto rnd = makeRandomScript(20, /*seed*/ 1337);
  runner.runScript(rnd);

  // A “bad smell” call for AST matching
  std::string copied = unsafeCopyToFixed("this_string_is_way_too_long_for_buffer");
  log(Level::Info, "unsafeCopyToFixed result: '", copied, "'");

  runner.summary();

  log(Level::Info, "demo finished");
  return 0;
}