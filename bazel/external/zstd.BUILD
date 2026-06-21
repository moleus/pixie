# Copyright 2018- The Pixie Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

load("@rules_cc//cc:defs.bzl", "cc_library")

licenses(["notice"])

exports_files(["LICENSE"])

# Decompression-only build of zstd: lib/common + lib/decompress, pure C (the
# x86_64 asm is excluded and disabled), with xxhash symbols namespaced to avoid
# clashing with the standalone xxHash dependency.
cc_library(
    name = "zstd",
    srcs = glob(
        [
            "lib/common/*.c",
            "lib/decompress/*.c",
        ],
    ),
    hdrs = glob([
        "lib/*.h",
        "lib/common/*.h",
        "lib/decompress/*.h",
    ]),
    copts = [
        "-DZSTD_DISABLE_ASM",
        "-DXXH_NAMESPACE=ZSTD_",
    ],
    includes = ["lib"],
    visibility = ["//visibility:public"],
)
