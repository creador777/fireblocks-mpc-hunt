#include "opus/telemetry_v2.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <string>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace opus {
namespace telemetry_v2 {
namespace {

constexpr const char* CELLS[] = {
    "r1.mta_proofs[victim]|flip_bit", "r1.mta_proofs[victim]|zero",
    "r1.mta_proofs[victim]|truncate",
    // Registrada por el parche extra_map_key: fuzzer_reachability_v2.cpp:70 la
    // produce y record_case exige selected.count(key)==1, asi que sin esta
    // linea el proceso muere en fail_closed(telemetry_publish_failed).
    "r4.si|extra_map_key",
};
constexpr const char* VERDICTS[] = {
    "CLEAN-SIGN", "CLEAN-REJECT", "INVALID-SIGNATURE",
    "STATE-CORRUPTION", "CRASH", "TIMEOUT", "HARNESS-FAULT",
};
constexpr int MAX_JOB_DOCUMENTS = 100000;

uint64_t monotonic_ns()
{
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

struct state {
    bool configured = false;
    bool claimed = false;
    bool fault_fired = false;
    std::string dir;
    std::string control_dir;
    std::string build_id;
    std::string compiler;
    std::string sanitizers;
    int job_index = -1;
    int parallelism = 1;
    uint64_t started_ns = 0;
    uint64_t execs = 0;
    uint64_t door_rejects = 0;
    uint64_t decoded = 0;
    std::map<std::string, uint64_t> selected;
    std::map<std::string, uint64_t> applied;
    std::map<std::string, uint64_t> not_applied;
    std::map<std::string, uint64_t> verdicts;
};

state& s() { static state value; return value; }

bool vocabulary(const std::string& value)
{
    if (value.empty() || value.size() > 96)
        return false;
    for (char c : value) {
        const bool ok = (c >= 'a' && c <= 'z') ||
                        (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '-' || c == '.' ||
                        c == '|' || c == '+' || c == '_';
        if (!ok)
            return false;
    }
    return true;
}

void quoted(std::string& out, const std::string& value)
{
    out += '"'; out += value; out += '"';
}

void emit_map(std::string& out, const std::map<std::string, uint64_t>& values)
{
    out += '{';
    bool first = true;
    for (const auto& kv : values) {
        if (!first) out += ',';
        first = false;
        quoted(out, kv.first);
        out += ':';
        out += std::to_string(kv.second);
    }
    out += '}';
}

bool mkdir_if_needed(const std::string& path)
{
    if (::mkdir(path.c_str(), 0700) == 0)
        return true;
    struct stat st {};
    return ::lstat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode) &&
           !S_ISLNK(st.st_mode);
}

bool claim_job()
{
    if (!s().configured)
        return false;
    if (s().claimed)
        return true;
    if (!mkdir_if_needed(s().dir) || !mkdir_if_needed(s().control_dir))
        return false;
    for (int index = 0; index < MAX_JOB_DOCUMENTS; ++index) {
        const std::string claim = s().control_dir + "/job-" +
                                  std::to_string(index);
        const int fd = ::open(claim.c_str(), O_WRONLY | O_CREAT | O_EXCL |
                                             O_NOFOLLOW, 0600);
        if (fd < 0)
            continue;
        const std::string owner = std::to_string(
            static_cast<long long>(::getpid())) + "\n";
        const bool ok = ::write(fd, owner.data(), owner.size()) ==
                            static_cast<ssize_t>(owner.size()) &&
                        ::fsync(fd) == 0;
        const bool closed = ::close(fd) == 0;
        if (!ok || !closed)
            return false;
        s().job_index = index;
        s().claimed = true;
        return true;
    }
    return false;
}

bool fault_selected(const char* name)
{
#if defined(OPUS_RT4_CANARY_FAULTS)
    const char* fault = std::getenv("OPUS_RT4_FAULT");
    const char* job = std::getenv("OPUS_RT4_FAULT_SLOT");
    if (!fault || std::string(fault) != name)
        return false;
    return s().job_index == (job ? std::atoi(job) : 0);
#else
    (void)name;
    return false;
#endif
}

bool write_all(int fd, const std::string& data)
{
    size_t offset = 0;
    while (offset < data.size()) {
        const ssize_t n = ::write(fd, data.data() + offset,
                                  data.size() - offset);
        if (n <= 0)
            return false;
        offset += static_cast<size_t>(n);
    }
    return true;
}

bool atomic_publish(const std::string& dest, const std::string& doc)
{
    const std::string tmp = dest + ".tmp." +
                            std::to_string(static_cast<long long>(::getpid()));
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL |
                                       O_NOFOLLOW, 0600);
    if (fd < 0)
        return false;
    if (fault_selected("death_before_flush")) {
        const std::string partial = "{\"schema\":";
        (void)::write(fd, partial.data(), partial.size());
        std::_Exit(92);
    }
    const bool ok = write_all(fd, doc) && ::fsync(fd) == 0;
    const bool closed = ::close(fd) == 0;
    if (!ok || !closed) {
        (void)::unlink(tmp.c_str());
        return false;
    }
    if (::rename(tmp.c_str(), dest.c_str()) != 0) {
        (void)::unlink(tmp.c_str());
        return false;
    }
    const int dfd = ::open(s().dir.c_str(), O_RDONLY | O_DIRECTORY |
                                           O_NOFOLLOW);
    if (dfd < 0)
        return false;
    const bool synced = ::fsync(dfd) == 0;
    const bool dir_closed = ::close(dfd) == 0;
    return synced && dir_closed;
}

} // namespace

bool configure(const char* dir, const char* control_dir, const char* build_id,
               const char* compiler, const char* sanitizers, int parallelism)
{
    if (!dir || !*dir || !control_dir || !*control_dir || !build_id ||
        parallelism < 1 || parallelism > 64)
        return false;
    const std::string build = build_id;
    const std::string comp = compiler ? compiler : "unknown";
    const std::string sans = sanitizers ? sanitizers : "unknown";
    if (!vocabulary(build) || !vocabulary(comp) || !vocabulary(sans))
        return false;

    s() = state{};
    s().configured = true;
    s().dir = dir;
    s().control_dir = control_dir;
    s().build_id = build;
    s().compiler = comp;
    s().sanitizers = sans;
    s().parallelism = parallelism;
    s().started_ns = monotonic_ns();
    for (const char* key : CELLS) {
        s().selected[key] = 0;
        s().applied[key] = 0;
        s().not_applied[key] = 0;
    }
    for (const char* key : VERDICTS)
        s().verdicts[key] = 0;
    return true;
}

bool record_door_reject()
{
    if (!claim_job())
        return false;
    if (!s().fault_fired && fault_selected("missing")) {
        s().fault_fired = true;
        std::_Exit(91);
    }
    ++s().execs;
    ++s().door_rejects;
    return publish();
}

bool record_case(const char* cell_key, bool was_applied, const char* verdict)
{
    if (!claim_job() || !cell_key || s().selected.count(cell_key) != 1)
        return false;
    if (!s().fault_fired && fault_selected("missing")) {
        s().fault_fired = true;
        std::_Exit(91);
    }
    ++s().execs;
    ++s().decoded;
    ++s().selected[cell_key];
    if (was_applied) {
        if (!verdict || s().verdicts.count(verdict) != 1)
            return false;
        ++s().applied[cell_key];
        ++s().verdicts[verdict];
    } else {
        ++s().not_applied[cell_key];
    }
    return publish();
}

bool publish()
{
    if (!s().configured || !s().claimed)
        return true;
    const int reported_index = fault_selected("duplicate") ? 0 : s().job_index;

    std::string doc;
    doc += "{\"schema\":\"rt4.telemetry/2\",\"identity\":{\"campaign\":\"reachability_v2_r4\",\"fuzzer\":\"opus_cmp_fuzzer_reachability_v2\"},\"build\":{\"id\":";
    quoted(doc, s().build_id);
    doc += ",\"compiler\":"; quoted(doc, s().compiler);
    doc += ",\"sanitizers\":"; quoted(doc, s().sanitizers);
    doc += "},\"process\":{\"job_index\":" +
           std::to_string(reported_index) +
           ",\"parallelism\":" + std::to_string(s().parallelism) +
           ",\"started_monotonic_ns\":" +
           std::to_string(s().started_ns) +
           ",\"updated_monotonic_ns\":" +
           std::to_string(monotonic_ns()) +
           "},\"counters\":{\"execs\":" + std::to_string(s().execs) +
           ",\"door_rejects\":" + std::to_string(s().door_rejects) +
           ",\"decoded\":" + std::to_string(s().decoded) +
           ",\"selected\":";
    emit_map(doc, s().selected);
    doc += ",\"applied\":"; emit_map(doc, s().applied);
    doc += ",\"not_applied\":"; emit_map(doc, s().not_applied);
    doc += ",\"verdicts\":"; emit_map(doc, s().verdicts);
    doc += "}}\n";
    if (fault_selected("truncated"))
        doc = "{\"schema\":";
    const std::string dest = s().dir + "/telemetry-job" +
                             std::to_string(s().job_index) + ".json";
    return atomic_publish(dest, doc);
}

} // namespace telemetry_v2
} // namespace opus
