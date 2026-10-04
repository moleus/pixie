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

// stirling_ch runs Stirling without the rest of the PEM and writes every pushed record batch
// into a ClickHouse server on the same node. Each table becomes a Memory table with a byte
// cap, so the node keeps a ring buffer and a central server reads it through a Distributed
// table. Rows get the node name and the pod of the local process, read from the host:
//   /proc/<pid>/cgroup        -> pod UID
//   /var/log/pods/<ns>_<pod>_<uid> -> namespace and pod name

#include <csignal>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <condition_variable>
#include <regex>
#include <thread>

#include <absl/base/internal/spinlock.h>
#include <absl/strings/str_replace.h>
#include <absl/strings/str_split.h>
#include <clickhouse/client.h>

#include "src/common/base/base.h"
#include "src/common/signal/signal.h"
#include "src/common/system/config.h"
#include "src/shared/upid/upid.h"
#include "src/stirling/core/output.h"
#include "src/stirling/core/pub_sub_manager.h"
#include "src/stirling/core/source_registry.h"
#include "src/stirling/stirling.h"

DEFINE_string(ch_host, "127.0.0.1", "ClickHouse host (native protocol).");
DEFINE_int32(ch_port, 9000, "ClickHouse native port.");
DEFINE_string(ch_user, "default", "ClickHouse user.");
DEFINE_string(ch_password, gflags::StringFromEnv("CH_PASSWORD", ""), "ClickHouse password.");
DEFINE_string(ch_database, "px", "ClickHouse database for the tables.");
DEFINE_string(ch_tables,
              "conn_stats,http_events,dns_events,redis_events,pgsql_events,mysql_events,"
              "kafka_events.beta,process_stats,network_stats",
              "Comma-separated list of Stirling tables to write.");
DEFINE_int64(ch_table_bytes, 16 << 20, "max_bytes_to_keep of each Memory table.");
DEFINE_int64(ch_max_string_bytes, 1024, "Strings longer than this are cut.");
DEFINE_int32(ch_queue_batches, 256, "Batches waiting for insert; more are dropped.");
DEFINE_string(node_name, gflags::StringFromEnv("NODE_NAME", ""), "Value of the node column.");
DEFINE_bool(ch_local_pods_only, false,
            "Write only rows of pods listed in this node's /var/log/pods. For nodes that share one "
            "kernel (k3d, kind): every node sees every process, this keeps one copy of each row.");
DEFINE_int32(timeout_secs, -1, "If non-negative, run this long and exit.");

using ::px::Status;
using ::px::stirling::IndexPublication;
using ::px::stirling::Stirling;
using ::px::stirling::stirlingpb::InfoClass;
using ::px::stirling::stirlingpb::Publish;
using ::px::types::ColumnWrapperRecordBatch;
using ::px::types::DataType;
using ::px::types::TabletID;

namespace {

Stirling* g_stirling = nullptr;
absl::flat_hash_map<uint64_t, InfoClass> g_table_info_map;
absl::flat_hash_set<std::string> g_enabled_tables;

std::string CHTableName(std::string_view stirling_name) {
  return absl::StrReplaceAll(stirling_name, {{".", "_"}});
}

std::string CHType(DataType t) {
  switch (t) {
    case DataType::BOOLEAN:
      return "UInt8";
    case DataType::INT64:
      return "Int64";
    case DataType::FLOAT64:
      return "Float64";
    case DataType::STRING:
      return "String";
    case DataType::TIME64NS:
      return "DateTime64(9)";
    default:
      return "";
  }
}

// ---------------------------------------------------------------------------------------------
// Pod of a local process. Cached by PID and process start time.
// ---------------------------------------------------------------------------------------------

struct ProcInfo {
  int64_t start_ts = 0;
  bool local_pod = false;
  std::string pod_uid;
  std::string ns;
  std::string pod;
  std::string comm;
};

class PodResolver {
 public:
  const ProcInfo& Resolve(const px::md::UPID& upid) {
    auto it = cache_.find(upid.pid());
    if (it != cache_.end() && it->second.start_ts == upid.start_ts()) {
      return it->second;
    }
    ProcInfo info;
    info.start_ts = upid.start_ts();
    const auto& cfg = px::system::Config::GetInstance();
    const std::filesystem::path proc = cfg.ToHostPath(absl::StrCat("/proc/", upid.pid()));
    std::ifstream comm(proc / "comm");
    std::getline(comm, info.comm);
    std::ifstream cg(proc / "cgroup");
    std::string line;
    static const std::regex kPodRe("pod([0-9a-f]{8}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{12})");
    std::smatch m;
    while (std::getline(cg, line)) {
      if (std::regex_search(line, m, kPodRe)) {
        info.pod_uid = absl::StrReplaceAll(m[1].str(), {{"_", "-"}});
        break;
      }
    }
    if (!info.pod_uid.empty()) {
      auto pod = LookupPod(info.pod_uid);
      if (pod != nullptr) {
        info.local_pod = true;
        info.ns = pod->first;
        info.pod = pod->second;
      }
    }
    if (cache_.size() > 65536) cache_.clear();
    return cache_[upid.pid()] = std::move(info);
  }

 private:
  const std::pair<std::string, std::string>* LookupPod(const std::string& uid) {
    auto it = pods_.find(uid);
    if (it != pods_.end()) return &it->second;
    // A new pod: list /var/log/pods again, at most once per second.
    auto now = std::chrono::steady_clock::now();
    if (now - last_scan_ < std::chrono::seconds(1)) return nullptr;
    last_scan_ = now;
    std::error_code ec;
    const auto dir = px::system::Config::GetInstance().ToHostPath("/var/log/pods");
    for (const auto& e : std::filesystem::directory_iterator(dir, ec)) {
      // Directory name: <namespace>_<pod>_<uid>. Namespace and pod names cannot hold '_'.
      std::vector<std::string> parts = absl::StrSplit(e.path().filename().string(), '_');
      if (parts.size() != 3) continue;
      pods_[parts[2]] = {parts[0], parts[1]};
    }
    it = pods_.find(uid);
    return it == pods_.end() ? nullptr : &it->second;
  }

  absl::flat_hash_map<uint32_t, ProcInfo> cache_;
  absl::flat_hash_map<std::string, std::pair<std::string, std::string>> pods_;
  std::chrono::steady_clock::time_point last_scan_;
};

// ---------------------------------------------------------------------------------------------
// ClickHouse writer: the Stirling thread converts and enqueues, one thread inserts.
// ---------------------------------------------------------------------------------------------

struct PendingInsert {
  std::string table;
  clickhouse::Block block;
};

class CHWriter {
 public:
  void Start() { thread_ = std::thread(&CHWriter::Loop, this); }

  void CreateTables(const Publish& pub) {
    std::lock_guard<std::mutex> lock(ddl_mu_);
    for (const auto& ic : pub.published_info_classes()) {
      const auto& schema = ic.schema();
      if (!g_enabled_tables.contains(schema.name())) continue;
      std::vector<std::string> cols;
      for (const auto& el : schema.elements()) {
        if (el.type() == DataType::UINT128) {
          cols.push_back(absl::StrCat("`", el.name(), "_hi` UInt64"));
          cols.push_back(absl::StrCat("`", el.name(), "_lo` UInt64"));
        } else {
          cols.push_back(absl::StrCat("`", el.name(), "` ", CHType(el.type())));
        }
      }
      for (const char* c : {"node", "namespace", "pod", "pod_uid", "comm"}) {
        cols.push_back(absl::StrCat("`", c, "` String"));
      }
      ddl_.push_back(absl::Substitute(
          "CREATE TABLE IF NOT EXISTS `$0`.`$1` ($2) ENGINE = Memory "
          "SETTINGS max_bytes_to_keep = $3, min_bytes_to_keep = $4",
          FLAGS_ch_database, CHTableName(schema.name()), absl::StrJoin(cols, ", "),
          FLAGS_ch_table_bytes, FLAGS_ch_table_bytes * 3 / 4));
    }
  }

  void Push(const InfoClass& info, const ColumnWrapperRecordBatch& rb) {
    const auto& schema = info.schema();
    if (rb.empty() || rb[0]->Size() == 0) return;
    const size_t n_all = rb[0]->Size();
    int upid_idx = -1;
    for (int i = 0; i < schema.elements_size(); ++i) {
      if (schema.elements(i).name() == "upid") upid_idx = i;
    }
    // Rows to write and their pods. Without a upid column every row is kept.
    // Copies, not pointers: Resolve() may rehash or clear the cache.
    std::vector<size_t> rows;
    std::vector<ProcInfo> procs;
    rows.reserve(n_all);
    for (size_t r = 0; r < n_all; ++r) {
      ProcInfo p;
      if (upid_idx >= 0) {
        p = resolver_.Resolve(px::md::UPID(rb[upid_idx]->Get<px::types::UInt128Value>(r).val));
        if (FLAGS_ch_local_pods_only && !p.local_pod) continue;
      }
      rows.push_back(r);
      procs.push_back(std::move(p));
    }
    if (rows.empty()) return;
    clickhouse::Block block;
    for (int i = 0; i < schema.elements_size(); ++i) {
      const auto& el = schema.elements(i);
      const auto& col = rb[i];
      switch (el.type()) {
        case DataType::BOOLEAN: {
          auto c = std::make_shared<clickhouse::ColumnUInt8>();
          for (size_t r : rows) c->Append(col->Get<px::types::BoolValue>(r).val);
          block.AppendColumn(el.name(), c);
          break;
        }
        case DataType::INT64: {
          auto c = std::make_shared<clickhouse::ColumnInt64>();
          for (size_t r : rows) c->Append(col->Get<px::types::Int64Value>(r).val);
          block.AppendColumn(el.name(), c);
          break;
        }
        case DataType::FLOAT64: {
          auto c = std::make_shared<clickhouse::ColumnFloat64>();
          for (size_t r : rows) c->Append(col->Get<px::types::Float64Value>(r).val);
          block.AppendColumn(el.name(), c);
          break;
        }
        case DataType::TIME64NS: {
          auto c = std::make_shared<clickhouse::ColumnDateTime64>(9);
          for (size_t r : rows) c->Append(col->Get<px::types::Time64NSValue>(r).val);
          block.AppendColumn(el.name(), c);
          break;
        }
        case DataType::STRING: {
          auto c = std::make_shared<clickhouse::ColumnString>();
          for (size_t r : rows) {
            std::string_view s = col->Get<px::types::StringValue>(r);
            c->Append(s.substr(0, FLAGS_ch_max_string_bytes));
          }
          block.AppendColumn(el.name(), c);
          break;
        }
        case DataType::UINT128: {
          auto hi = std::make_shared<clickhouse::ColumnUInt64>();
          auto lo = std::make_shared<clickhouse::ColumnUInt64>();
          for (size_t r : rows) {
            const auto& v = col->Get<px::types::UInt128Value>(r);
            hi->Append(v.High64());
            lo->Append(v.Low64());
          }
          block.AppendColumn(el.name() + "_hi", hi);
          block.AppendColumn(el.name() + "_lo", lo);
          break;
        }
        default:
          return;
      }
    }
    auto node = std::make_shared<clickhouse::ColumnString>();
    auto ns = std::make_shared<clickhouse::ColumnString>();
    auto pod = std::make_shared<clickhouse::ColumnString>();
    auto pod_uid = std::make_shared<clickhouse::ColumnString>();
    auto comm = std::make_shared<clickhouse::ColumnString>();
    for (const ProcInfo& p : procs) {
      node->Append(FLAGS_node_name);
      ns->Append(p.ns);
      pod->Append(p.pod);
      pod_uid->Append(p.pod_uid);
      comm->Append(p.comm);
    }
    block.AppendColumn("node", node);
    block.AppendColumn("namespace", ns);
    block.AppendColumn("pod", pod);
    block.AppendColumn("pod_uid", pod_uid);
    block.AppendColumn("comm", comm);

    std::lock_guard<std::mutex> lock(mu_);
    if (queue_.size() >= static_cast<size_t>(FLAGS_ch_queue_batches)) {
      ++dropped_batches_;
      return;
    }
    queue_.push_back({absl::StrCat(FLAGS_ch_database, ".", CHTableName(schema.name())),
                      std::move(block)});
    cv_.notify_one();
  }

 private:
  void Loop() {
    std::unique_ptr<clickhouse::Client> client;
    bool ddl_done = false;
    auto last_report = std::chrono::steady_clock::now();
    while (true) {
      try {
        if (client == nullptr) {
          client = std::make_unique<clickhouse::Client>(clickhouse::ClientOptions()
                                                            .SetHost(FLAGS_ch_host)
                                                            .SetPort(FLAGS_ch_port)
                                                            .SetUser(FLAGS_ch_user)
                                                            .SetPassword(FLAGS_ch_password));
          ddl_done = false;
        }
        if (!ddl_done) {
          std::lock_guard<std::mutex> lock(ddl_mu_);
          client->Execute(absl::StrCat("CREATE DATABASE IF NOT EXISTS `", FLAGS_ch_database, "`"));
          for (const auto& q : ddl_) client->Execute(q);
          ddl_done = true;
        }
        PendingInsert ins;
        {
          std::unique_lock<std::mutex> lock(mu_);
          cv_.wait_for(lock, std::chrono::seconds(1), [this] { return !queue_.empty(); });
          if (queue_.empty()) continue;
          ins = std::move(queue_.front());
          queue_.pop_front();
        }
        client->Insert(ins.table, ins.block);
        ++inserted_batches_;
        inserted_rows_ += ins.block.GetRowCount();
      } catch (const std::exception& e) {
        LOG_EVERY_N(WARNING, 10) << "ClickHouse insert failed: " << e.what();
        ++failed_batches_;
        client.reset();
        std::this_thread::sleep_for(std::chrono::seconds(1));
      }
      auto now = std::chrono::steady_clock::now();
      if (now - last_report > std::chrono::seconds(60)) {
        last_report = now;
        LOG(INFO) << absl::Substitute("ch_writer inserted_batches=$0 rows=$1 failed=$2 dropped=$3",
                                      inserted_batches_, inserted_rows_, failed_batches_,
                                      dropped_batches_);
      }
    }
  }

  PodResolver resolver_;  // Used only by the Stirling thread (Push).
  std::mutex ddl_mu_;
  std::vector<std::string> ddl_;
  std::mutex mu_;
  std::condition_variable cv_;
  std::deque<PendingInsert> queue_;
  uint64_t dropped_batches_ = 0;
  uint64_t inserted_batches_ = 0;
  uint64_t inserted_rows_ = 0;
  uint64_t failed_batches_ = 0;
  std::thread thread_;
};

CHWriter* g_writer = nullptr;

Status Callback(uint64_t table_id, TabletID /* tablet_id */,
                std::unique_ptr<ColumnWrapperRecordBatch> record_batch) {
  auto iter = g_table_info_map.find(table_id);
  if (iter == g_table_info_map.end()) {
    return px::error::Internal("Encountered unknown table id $0", table_id);
  }
  if (g_enabled_tables.contains(iter->second.schema().name())) {
    g_writer->Push(iter->second, *record_batch);
  }
  return Status::OK();
}

void TerminationHandler(int signum) {
  // Stop() releases BPF resources, which would otherwise leak.
  if (g_stirling != nullptr) g_stirling->Stop();
  exit(signum);
}

}  // namespace

int main(int argc, char** argv) {
  signal(SIGINT, TerminationHandler);
  signal(SIGQUIT, TerminationHandler);
  signal(SIGTERM, TerminationHandler);
  signal(SIGHUP, TerminationHandler);

  px::EnvironmentGuard env_guard(&argc, argv);
  g_enabled_tables = absl::StrSplit(FLAGS_ch_tables, ",", absl::SkipWhitespace());

  std::unique_ptr<Stirling> stirling =
      Stirling::Create(px::stirling::CreateSourceRegistryFromFlag());
  g_stirling = stirling.get();
  stirling->RegisterUserDebugSignalHandlers();

  Publish publication;
  stirling->GetPublishProto(&publication);
  IndexPublication(publication, &g_table_info_map);

  CHWriter writer;
  g_writer = &writer;
  writer.CreateTables(publication);
  writer.Start();

  stirling->RegisterDataPushCallback(Callback);
  std::thread run_thread = std::thread(&Stirling::Run, stirling.get());
  PX_CHECK_OK(stirling->WaitUntilRunning(std::chrono::seconds(5)));
  LOG(INFO) << "stirling_ch running, node=" << FLAGS_node_name;

  if (FLAGS_timeout_secs >= 0) {
    std::this_thread::sleep_for(std::chrono::seconds(FLAGS_timeout_secs));
    stirling->Stop();
    _exit(0);
  }
  run_thread.join();
  return 0;
}
