#pragma once

// Canary telemetry contract: counters only, no unit-derived data. Each
// libFuzzer exec-generation claims a monotonic job id after it receives its
// first input. Documents use checked write+fsync+rename; an unmatched claim,
// invalid document or sidecar blocks aggregation.

#include <cstdint>

namespace opus {
namespace telemetry_v2 {

bool record_door_reject();
bool record_case(const char* cell_key, bool applied, const char* verdict);
bool publish();

bool configure(const char* dir, const char* control_dir, const char* build_id,
               const char* compiler, const char* sanitizers, int parallelism);

} // namespace telemetry_v2
} // namespace opus
