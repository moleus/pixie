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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <deque>

#include "src/common/base/types.h"
#include "src/stirling/source_connectors/socket_tracer/protocols/kafka/common/types.h"
#include "src/stirling/source_connectors/socket_tracer/protocols/kafka/parse.h"
#include "src/stirling/source_connectors/socket_tracer/protocols/kafka/stitcher.h"
#include "src/stirling/source_connectors/socket_tracer/protocols/kafka/test_data.h"

namespace px {
namespace stirling {
namespace protocols {
namespace kafka {

TEST(KafkaStitcherTest, BasicMatching) {
  std::deque<Packet> req_packets;
  std::deque<Packet> resp_packets;
  State state{};
  RecordsWithErrorCount<Record> result;

  result = StitchFrames(&req_packets, &resp_packets, &state);
  EXPECT_TRUE(resp_packets.empty());
  EXPECT_TRUE(req_packets.empty());
  EXPECT_EQ(result.error_count, 0);
  EXPECT_EQ(result.records.size(), 0);

  req_packets.push_back(testdata::kProduceReqPacket);

  result = StitchFrames(&req_packets, &resp_packets, &state);
  EXPECT_TRUE(resp_packets.empty());
  EXPECT_EQ(req_packets.size(), 1);
  EXPECT_EQ(result.error_count, 0);
  EXPECT_EQ(result.records.size(), 0);

  resp_packets.push_back(testdata::kProduceRespPacket);

  result = StitchFrames(&req_packets, &resp_packets, &state);
  EXPECT_TRUE(resp_packets.empty());
  EXPECT_EQ(req_packets.size(), 0);
  EXPECT_EQ(result.error_count, 0);
  EXPECT_EQ(result.records.size(), 1);
  EXPECT_EQ(
      result.records[0].req.msg,
      "{\"transactional_id\":\"\",\"acks\":1,\"timeout_ms\":1500,\"topics\":[{\"name\":"
      "\"quickstart-events\",\"partitions\":[{\"index\":0,\"message_set\":{\"size\":91}}]}]}");
  EXPECT_EQ(result.records[0].resp.msg,
            "{\"topics\":[{\"name\":\"quickstart-events\",\"partitions\":[{\"index\":0,\"error_"
            "code\":0,\"base_offset\":0,\"log_append_time_ms\":-1,\"log_start_offset\":0,"
            "\"record_errors\":[],\"error_message\":\"\"}]}],\"throttle_time_ms\":0}");
}

// The live-cluster scenario the inference fix targets: a Kafka request arrives split
// across reads (long messages, TCP coalescing, TLS/JSSE chunks). Once the connection
// is classified (see bcc_bpf/protocol_inference_test), the stream parser must
// reassemble the frame across reads and the stitcher must still emit a fully decoded
// kafka_events Record. This walks raw bytes -> ParseFrame (reassembly) ->
// StitchFrames -> Record, end to end in user space.
TEST(KafkaStitcherTest, SplitReadReassemblesIntoDecodedRecord) {
  auto req_view = CreateStringView<char>(CharArrayStringView<uint8_t>(testdata::kProduceRequest));
  auto resp_view = CreateStringView<char>(CharArrayStringView<uint8_t>(testdata::kProduceResponse));

  // A partial first read must NOT misparse -- the parser asks for more data.
  Packet probe_packet;
  State probe_state{};
  auto partial = req_view.substr(0, req_view.size() - 16);
  EXPECT_EQ(ParseState::kNeedsMoreData,
            ParseFrame(message_type_t::kRequest, &partial, &probe_packet, &probe_state));

  // Once the rest of the bytes arrive, the full request reassembles into one frame.
  Packet req_packet;
  State req_state{};
  auto full_req = req_view;
  ASSERT_EQ(ParseState::kSuccess,
            ParseFrame(message_type_t::kRequest, &full_req, &req_packet, &req_state));

  // Parse the matching response (the recv path only accepts a response whose
  // correlation id was seen on the send path).
  Packet resp_packet;
  State resp_state{};
  resp_state.seen_correlation_ids.insert(req_packet.correlation_id);
  ASSERT_EQ(ParseState::kSuccess,
            ParseFrame(message_type_t::kResponse, &resp_view, &resp_packet, &resp_state));

  // The reassembled exchange stitches into exactly one decoded kafka_events Record.
  req_packet.timestamp_ns = 1;
  resp_packet.timestamp_ns = 2;
  std::deque<Packet> req_packets{req_packet};
  std::deque<Packet> resp_packets{resp_packet};
  State stitch_state{};
  RecordsWithErrorCount<Record> result = StitchFrames(&req_packets, &resp_packets, &stitch_state);
  ASSERT_EQ(result.records.size(), 1u);
  EXPECT_THAT(result.records[0].req.msg, ::testing::HasSubstr("quickstart-events"));
}

}  // namespace kafka
}  // namespace protocols
}  // namespace stirling
}  // namespace px
