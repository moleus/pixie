/*
 * Copyright 2018- The Pixie Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <algorithm>
#include <filesystem>
#include <memory>
#include <utility>

#include <absl/strings/str_format.h>

#include "src/common/base/logging.h"
#include "src/common/fs/fs_wrapper.h"
#include "src/common/system/proc_parser.h"
#include "src/common/system/proc_pid_path.h"
#include "src/common/system/scoped_namespace.h"
#include "src/stirling/source_connectors/perf_profiler/java/agent/agent_hash.h"
#include "src/stirling/source_connectors/perf_profiler/java/agent/raw_symbol_update.h"
#include "src/stirling/source_connectors/perf_profiler/java/attach.h"
#include "src/stirling/source_connectors/perf_profiler/java/px_jattach/px_jattach.h"
#include "src/stirling/utils/proc_path_tools.h"

extern "C" {
// NOLINTNEXTLINE: build/include_subdir
#include "jattach.h"
}

namespace px {
namespace stirling {
namespace java {

using ::px::system::ProcPidRootPath;

namespace {
StatusOr<uint32_t> GetNSPid(const int pid) {
  const system::ProcParser proc_parser;
  std::vector<std::string> ns_pids;
  PX_RETURN_IF_ERROR(proc_parser.ReadNSPid(pid, &ns_pids));
  const std::string& ns_pid_string = ns_pids.back();
  const uint32_t ns_pid = std::stol(ns_pid_string);
  return ns_pid;
}

bool TestDLOpen(const std::string& so_lib_file_path) {
  if (!fs::Exists(so_lib_file_path)) {
    LOG(FATAL) << absl::Substitute("Could not find so file: $0", so_lib_file_path);
  }

  // Reset the error message in the dynamic linking library. We do this prior to any call to
  // dlxyz() as general good practice.
  dlerror();
  void* h = dlopen(so_lib_file_path.c_str(), RTLD_LAZY);

  if (h == nullptr) {
    VLOG(1) << absl::Substitute("TestDLOpen(), dlopen() failure: $0.", dlerror());
    return false;
  }

  dlerror();
  auto test_fn = (uint64_t(*)(void))dlsym(h, "PixieJavaAgentTestFn");

  if (test_fn == nullptr) {
    // Keeping this in the logs as a warning because we expect to not link (above) vs. not see the
    // test function succeed. If we see this message, it is a strange outcome.
    LOG(WARNING) << absl::Substitute("TestDLOpen(), dlsym() failure: $0.", dlerror());
    return false;
  }

  // TODO(jps): Move expected_test_fn_result to "shared."
  constexpr uint64_t expected_test_fn_result = 42;
  const uint64_t observed_test_fn_result = test_fn();

  if (observed_test_fn_result != expected_test_fn_result) {
    // Keeping this in the logs, same reasoning as for test_fn == nullptr.
    char const* const msg = "TestDLOpen(), test function returned: $0, expected $1.";
    LOG(WARNING) << absl::Substitute(msg, observed_test_fn_result, expected_test_fn_result);
    return false;
  }
  VLOG(1) << absl::Substitute("TestDLOpen(): Success for $0.", so_lib_file_path);
  return true;
}

// ---- Java-agent (pixie-jsse) helpers --------------------------------------------------------
// These support loading a *Java agent jar* (vs. a JVMTI .so) via jattach's built-in `instrument`
// agent. They deliberately use a SEPARATE artifacts path from the JVMTI symbolization flow so a
// single JVM can be both profiled (JVMTI .so) and TLS-traced (jsse .jar) without path collisions.

bool IsJar(const std::filesystem::path& p) { return p.extension() == ".jar"; }

// The pixie-jsse artifacts dir as seen FROM the target's mount namespace (a plain /tmp path).
// Passed to the JVM `instrument` agent, which resolves it inside the broker.
std::filesystem::path JSSEArtifactsArg(const struct upid_t& upid) {
  return absl::Substitute("/tmp/px-jsse-agent-$0-$1", upid.pid, upid.start_time_ticks);
}

// The same dir as seen FROM stirling (via /proc/<pid>/root/tmp), used to stage the files.
std::filesystem::path JSSEArtifactsInTarget(const struct upid_t& upid) {
  return ProcPidRootPath(
      upid.pid, "tmp", absl::Substitute("px-jsse-agent-$0-$1", upid.pid, upid.start_time_ticks));
}

// Loadability check only (no PixieJavaAgentTestFn requirement): a proxy for "the JVM will be
// able to System.load() this .so against the libc in the target namespace".
bool CanDLOpen(const std::string& so_path) {
  dlerror();
  void* h = dlopen(so_path.c_str(), RTLD_LAZY);
  if (h == nullptr) {
    VLOG(1) << absl::Substitute("CanDLOpen() failure for $0: $1", so_path, dlerror());
    return false;
  }
  return true;
}
}  // namespace

std::filesystem::path AgentArtifactsPathArg(const struct upid_t& upid) {
  // This is used as the argument passed into the Pixie JVMTI symbolization agent.
  // The agent itself is responsible for adding the suffix "-(PX_JVMTI_AGENT_HASH)" to the path.
  char const* const kPathTemplate = "/tmp/px-java-symbolization-artifacts-$0-$1";
  return absl::Substitute(kPathTemplate, upid.pid, upid.start_time_ticks);
}

void AgentAttachApp::SetTargetUIDAndGIDOrDie() {
  // Get the uid & gid of the target process. Will need these to downgrade the
  // uid & gid of the file that we create (we are root).
  const std::string proc_path = absl::Substitute("/proc/$0", target_upid_.pid);
  const struct stat sb = fs::Stat(proc_path).ConsumeValueOrDie();
  target_uid_ = sb.st_uid;
  target_gid_ = sb.st_gid;
}

void AgentAttachApp::CreateArtifactsPathOrDie() {
  // TODO(jps): uniquify the artifacts path using the Stirling self pid.

  // Create Java artifacts path in target container mount namespace, and chown to target uid+gid.
  const std::filesystem::path artifacts_path = StirlingArtifactsPath(target_upid_);

  if (fs::Exists(artifacts_path)) {
    // If the symbolizaton directory exists, when we get here, it means that another Stirling
    // instance has attempted to attach an agent *at the same time* as this Stirling process.
    // Otherwise, Stirling would have used the pre-existing symbol file (and therefore would
    // not have attempted to attach an agent).
    const std::filesystem::path symbol_file_path = StirlingSymbolFilePath(target_upid_);
    if (fs::Exists(symbol_file_path)) {
      // The other Stirling instance injected a symbolization agent and created a symbol file.
      std::exit(0);
    }

    // Still waiting on the other Stirling instance? We don't know. Error out.
    char const* const fmt = "Conflicting symbolization artifacts path detected: $0.";
    LOG(FATAL) << absl::Substitute(fmt, artifacts_path.string());
  }

  // As with the agent libs, the path containing them need to belong to the target process.
  PX_EXIT_IF_ERROR(fs::CreateDirectories(artifacts_path));
  PX_EXIT_IF_ERROR(fs::Chown(artifacts_path, target_uid_, target_gid_));
}

void AgentAttachApp::CopyAgentLibsOrDie() {
  // This is only invoked if the target pid is in a subordinate namespace.
  // Here, we copy the .so libs into the tmp path in that mount namespace.
  // We also change the file ownership such that the target process sees itself as the owner
  // of the file (necessary because some Java versions may refuse to inject an agent otherwise).

  // It will be ok to overwrite existing.
  const auto copy_options = std::filesystem::copy_options::overwrite_existing;

  // Copy each file and downgrade ownership.
  for (const std::filesystem::path& src_path : agent_libs_) {
    const std::filesystem::path artifacts_path = StirlingArtifactsPath(target_upid_);
    const std::filesystem::path basename = std::filesystem::path(src_path).filename();
    const std::filesystem::path dst_path = artifacts_path / basename;

    PX_EXIT_IF_ERROR(fs::Copy(src_path, dst_path, copy_options));
    PX_EXIT_IF_ERROR(fs::Chown(dst_path, target_uid_, target_gid_));
  }

  for (std::filesystem::path& agent_lib : agent_libs_) {
    // Mutate the values in agent_libs_ so that later, when we enter the namespace
    // of the target process, we use the correctly scoped file path.
    const std::filesystem::path artifacts_path = AgentArtifactsPath(target_upid_);
    const std::filesystem::path basename = std::filesystem::path(agent_lib).filename();
    agent_lib = artifacts_path / basename;
  }
}

void AgentAttachApp::SelectLibWithDLOpenOrDie() {
  // Enter pid & mount namespace for target pid so that use of dlopen correctly links
  // vs. the available libs in that namespace.
  PX_ASSIGN_OR(std::unique_ptr<system::ScopedNamespace> pid_scoped_namespace,
               system::ScopedNamespace::Create(target_upid_.pid, "pid"),
               { LOG(FATAL) << "Could not enter pid namespace."; });
  PX_ASSIGN_OR(std::unique_ptr<system::ScopedNamespace> mnt_scoped_namespace,
               system::ScopedNamespace::Create(target_upid_.pid, "mnt"),
               { LOG(FATAL) << "Could not enter mnt namespace."; });

  for (const std::filesystem::path& lib : agent_libs_) {
    // Set the member lib_so_path_, then test it with dlopen().
    lib_so_path_ = lib;

    if (TestDLOpen(lib_so_path_)) {
      // Success.
      char const* const msg = "SelectLibWithDLOpenOrDie(). Tested: $0, success.";
      VLOG(1) << absl::Substitute(msg, lib_so_path_);
      return;
    }
    // Failure; move on to the next candidate lib.
    VLOG(1) << absl::Substitute("SelectLibWithDLOpenOrDie(). Tested: $0, failure.", lib_so_path_);
  }

  // All the libs failed: die now.
  LOG(FATAL) << "SelectLibWithDLOpenOrDie(). Could not find a valid px java agent lib.";
}

void AgentAttachApp::AttachOrDie() {
  const std::string argent_args = AgentArtifactsPathArg(target_upid_).string();
  constexpr int argc = 4;
  const char* argv[argc] = {"load", lib_so_path_.c_str(), "true", argent_args.c_str()};
  const int r = jattach(target_upid_.pid, argc, argv);
  char const* const msg = "AgentAttachApp finished. pid: $0, lib: $1, exit code: $2";
  LOG(INFO) << absl::Substitute(msg, target_upid_.pid, lib_so_path_, r);
  if (r != 0) {
    std::exit(r);
  }
}

bool AgentAttachApp::IsJavaAgentMode() const {
  return std::any_of(agent_libs_.begin(), agent_libs_.end(),
                     [](const std::filesystem::path& p) { return IsJar(p); });
}

void AgentAttachApp::CreateJSSEArtifactsPathOrDie() {
  // Staging dir for the jsse jar + native .so inside the target's mount namespace. Unlike the
  // JVMTI path, there is no symbol-file conflict to detect, so a pre-existing dir is fine
  // (idempotent re-injection just overwrites).
  const std::filesystem::path artifacts_path = JSSEArtifactsInTarget(target_upid_);
  if (!fs::Exists(artifacts_path)) {
    PX_EXIT_IF_ERROR(fs::CreateDirectories(artifacts_path));
    PX_EXIT_IF_ERROR(fs::Chown(artifacts_path, target_uid_, target_gid_));
  }
}

void AgentAttachApp::CopyJSSELibsOrDie() {
  // Copy the jar + .so into the target namespace's /tmp and chown to the target uid/gid (some
  // JVMs refuse to load agent files they don't own), then rewrite agent_libs_ to the paths the
  // TARGET process will see (plain /tmp/...).
  const auto copy_options = std::filesystem::copy_options::overwrite_existing;
  const std::filesystem::path artifacts_in_target = JSSEArtifactsInTarget(target_upid_);
  for (std::filesystem::path& lib : agent_libs_) {
    const std::filesystem::path dst_path = artifacts_in_target / lib.filename();
    PX_EXIT_IF_ERROR(fs::Copy(lib, dst_path, copy_options));
    PX_EXIT_IF_ERROR(fs::Chown(dst_path, target_uid_, target_gid_));
    lib = JSSEArtifactsArg(target_upid_) / lib.filename();
  }
}

void AgentAttachApp::AttachJavaAgentOrDie() {
  // Identify the agent jar, then pick a loadable native .so among the remaining libs (entering
  // the target namespace so dlopen resolves against the libc that is actually present there).
  std::filesystem::path jar;
  for (const auto& lib : agent_libs_) {
    if (IsJar(lib)) {
      jar = lib;
      break;
    }
  }
  if (jar.empty()) {
    LOG(FATAL) << "Java-agent mode selected, but no .jar found among the agent libs.";
  }

  std::string selected_so;
  {
    PX_ASSIGN_OR(std::unique_ptr<system::ScopedNamespace> pid_scoped_namespace,
                 system::ScopedNamespace::Create(target_upid_.pid, "pid"),
                 { LOG(FATAL) << "Could not enter pid namespace."; });
    PX_ASSIGN_OR(std::unique_ptr<system::ScopedNamespace> mnt_scoped_namespace,
                 system::ScopedNamespace::Create(target_upid_.pid, "mnt"),
                 { LOG(FATAL) << "Could not enter mnt namespace."; });
    for (const std::filesystem::path& lib : agent_libs_) {
      if (IsJar(lib)) {
        continue;
      }
      if (CanDLOpen(lib.string())) {
        selected_so = lib.string();
        break;
      }
      VLOG(1) << absl::Substitute("AttachJavaAgentOrDie(): $0 not loadable here, next.",
                                  lib.string());
    }
  }
  if (selected_so.empty()) {
    LOG(FATAL) << "Could not find a loadable native .so for the pixie-jsse agent.";
  }

  // jattach `load instrument false "<jar>=<opts>"`: the JVM's built-in JPLIS (`instrument`) agent
  // loads <jar> as a Java agent and calls agentmain(<opts>). The pixie-jsse agent treats <opts>
  // as the path to the native .so it must System.load(). No broker restart, no broker config.
  const std::string opts = absl::Substitute("$0=$1", jar.string(), selected_so);
  constexpr int argc = 4;
  const char* argv[argc] = {"load", "instrument", "false", opts.c_str()};
  const int r = jattach(target_upid_.pid, argc, argv);
  char const* const msg = "pixie-jsse agent attach finished. pid: $0, jar: $1, so: $2, exit: $3";
  LOG(INFO) << absl::Substitute(msg, target_upid_.pid, jar.string(), selected_so, r);
  if (r != 0) {
    std::exit(r);
  }
}

void AgentAttachApp::Attach() {
  // First, sleep for just a little bit of time. In testing, we observed the Java process get
  // into a bad state if the attacher tried to attach to soon after the Java process was started.
  // While this may be unlikely in a prod. scenario, here, we give time for the Java process
  // to get past its 'primordial' phase and into its 'live' phase.
  // TODO(jps): Remove once we correctly handle JVM phase inside of the agent.
  std::this_thread::sleep_for(std::chrono::milliseconds(250));

  const uint32_t target_ns_pid = GetNSPid(target_upid_.pid).ConsumeValueOrDie();
  char const* const msg = "AgentAttachApp(). target_pid: $0, target_ns_pid: $1.";
  VLOG(1) << absl::Substitute(msg, target_upid_.pid, target_ns_pid);

  SetTargetUIDAndGIDOrDie();

  // Java-agent (pixie-jsse .jar) vs. JVMTI (.so) injection take separate, non-colliding paths.
  if (IsJavaAgentMode()) {
    CreateJSSEArtifactsPathOrDie();
    if (target_ns_pid != target_upid_.pid) {
      CopyJSSELibsOrDie();
    }
    AttachJavaAgentOrDie();
    return;
  }

  CreateArtifactsPathOrDie();

  if (target_ns_pid != target_upid_.pid) {
    // If the target Java process is in a subordinate namespace, copy the agent libs into the
    // artifacts path (in /tmp) inside of that namespace (for visibility to the target process).
    // Skip this otherwise, to not pollute the tmp space.
    CopyAgentLibsOrDie();
  }

  // We compile one agent lib for each libc implementation we are aware of and support (currently,
  // those are glibc & musl). SelectLibWithDLOpenOrDie() enters the namespace of the target process
  // and tests each lib until it finds one that it can successfully dlopen and use.
  SelectLibWithDLOpenOrDie();

  // Having determined a lib that is likely to link in the target environment, we invoke the
  // well crafted code in jattach (https://github.com/apangin/jattach) to inject the library
  // as a JVMTI agent.
  AttachOrDie();
}

AgentAttachApp::AgentAttachApp(const struct upid_t& upid,
                               const std::vector<std::filesystem::path>& agent_libs)
    : target_upid_(upid), agent_libs_(agent_libs) {}

}  // namespace java
}  // namespace stirling
}  // namespace px

int main(int argc, char** argv) {
  px::EnvironmentGuard env_guard(&argc, argv);

  constexpr int kNumExpectedArgs = 4;
  if (argc != kNumExpectedArgs) {
    char const* const msg = "Wrong number of arguments. Expected $0, found $1.";
    LOG(FATAL) << absl::Substitute(msg, kNumExpectedArgs, argc);
  }

  uint32_t pid;
  uint64_t start_time_ticks;

  if (!absl::SimpleAtoi(argv[1], &pid)) {
    LOG(FATAL) << absl::Substitute(R"(Failed to parse "$0" to pid.))", argv[1]);
  }
  if (!absl::SimpleAtoi(argv[2], &start_time_ticks)) {
    LOG(FATAL) << absl::Substitute(R"(Failed to parse "$0" to start_time_ticks.)", argv[2]);
  }

  const struct upid_t target_upid = {{pid}, start_time_ticks};

  const std::vector<std::string_view> libs = absl::StrSplit(argv[3], ",");
  std::vector<std::filesystem::path> lib_paths;
  for (const auto lib : libs) {
    lib_paths.push_back(lib);
  }

  // Create an attacher.
  px::stirling::java::AgentAttachApp attacher(target_upid, lib_paths);

  // The attacher will call std::exit with an appropriate value if anything fails.
  attacher.Attach();

  // If we get here, everything has worked. Success!!
  return 0;
}
