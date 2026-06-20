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

#include "src/stirling/obj_tools/dwarf_reader.h"

#include "src/common/testing/test_environment.h"
#include "src/common/testing/testing.h"

namespace px {
namespace stirling {
namespace obj_tools {

using ::px::operator<<;

TEST(GolangStackABIModel, FunctionParameters) {
  std::unique_ptr<ABICallingConventionModel> abi_model =
      ABICallingConventionModel::Create(ABI::kGolangStack);
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 8, 8, 1, false),
                   (VarLocation{LocationType::kStack, 0}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 4, 4, 1, false),
                   (VarLocation{LocationType::kStack, 8}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 4, 4, 1, false),
                   (VarLocation{LocationType::kStack, 12}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 4, 4, 1, false),
                   (VarLocation{LocationType::kStack, 16}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 8, 4, 2, false),
                   (VarLocation{LocationType::kStack, 20}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 8, 8, 1, false),
                   (VarLocation{LocationType::kStack, 32}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 2, 2, 1, false),
                   (VarLocation{LocationType::kStack, 40}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 120, 8, 15, false),
                   (VarLocation{LocationType::kStack, 48}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 8, 8, 1, false),
                   (VarLocation{LocationType::kStack, 168}));
}

TEST(GolangRegisterABIModel, FunctionParameters) {
  std::unique_ptr<ABICallingConventionModel> abi_model =
      ABICallingConventionModel::Create(ABI::kGolangRegister);
  // Go's register ABI uses an architecture-specific integer register sequence
  // (amd64: RAX,RBX,RCX,RDI,RSI,R8,R9,R10,R11; arm64: R0..R15). For this call
  // sequence the assigned offsets and the stack-spill point are identical across
  // architectures; only the register names differ. See GolangRegABIModel in
  // abi_model.cc. The arm64 expectations exercise the #if defined(__aarch64__)
  // register table when the test is cross-compiled and run under qemu.
#if defined(__aarch64__)
  const RegisterName a0 = RegisterName::kR0, a1 = RegisterName::kR1, a2 = RegisterName::kR2,
                     a3 = RegisterName::kR3, a4 = RegisterName::kR4, a5 = RegisterName::kR5,
                     a6 = RegisterName::kR6, a7 = RegisterName::kR7, a8 = RegisterName::kR8Arm;
#else
  const RegisterName a0 = RegisterName::kRAX, a1 = RegisterName::kRBX, a2 = RegisterName::kRCX,
                     a3 = RegisterName::kRDI, a4 = RegisterName::kRSI, a5 = RegisterName::kR8,
                     a6 = RegisterName::kR9, a7 = RegisterName::kR10, a8 = RegisterName::kR11;
#endif
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 8, 8, 1, false),
                   (VarLocation{LocationType::kRegister, 0, {a0}}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 4, 4, 1, false),
                   (VarLocation{LocationType::kRegister, 8, {a1}}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 4, 4, 1, false),
                   (VarLocation{LocationType::kRegister, 16, {a2}}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 4, 4, 1, false),
                   (VarLocation{LocationType::kRegister, 24, {a3}}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 8, 4, 2, false),
                   (VarLocation{LocationType::kRegister, 32, {a4, a5}}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 8, 8, 1, false),
                   (VarLocation{LocationType::kRegister, 48, {a6}}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 2, 2, 1, false),
                   (VarLocation{LocationType::kRegister, 56, {a7}}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 120, 8, 15, false),
                   (VarLocation{LocationType::kStack, 0}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 8, 8, 1, false),
                   (VarLocation{LocationType::kRegister, 64, {a8}}));
}

TEST(SystemVAMD64ABIModel, FunctionParameters) {
  std::unique_ptr<ABICallingConventionModel> abi_model =
      ABICallingConventionModel::Create(ABI::kSystemVAMD64);
  // The C/C++ calling convention is architecture specific: System V AMD64 passes
  // up to 6 integer args (RDI,RSI,RDX,RCX,R8,R9) while AAPCS64 (arm64) passes up
  // to 8 (X0..X7 == R0..R7). The extra two arm64 registers change where this
  // sequence spills to the stack, so the expectations genuinely diverge below
  // (not just register names). See SysVABIModel in abi_model.cc.
#if defined(__aarch64__)
  // AAPCS64: 8 integer arg registers, so the 7th and 9th values that spill to the
  // stack on amd64 still fit in X6/X7 here.
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 8, 8, 1, false),
                   (VarLocation{LocationType::kRegister, 0, {RegisterName::kR0}}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 4, 4, 1, false),
                   (VarLocation{LocationType::kRegister, 8, {RegisterName::kR1}}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 4, 4, 1, false),
                   (VarLocation{LocationType::kRegister, 16, {RegisterName::kR2}}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 4, 4, 1, false),
                   (VarLocation{LocationType::kRegister, 24, {RegisterName::kR3}}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 8, 4, 2, false),
                   (VarLocation{LocationType::kRegister, 32, {RegisterName::kR4}}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 8, 8, 1, false),
                   (VarLocation{LocationType::kRegister, 40, {RegisterName::kR5}}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 2, 2, 1, false),
                   (VarLocation{LocationType::kRegister, 48, {RegisterName::kR6}}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 120, 8, 15, false),
                   (VarLocation{LocationType::kStack, 0}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 8, 8, 1, false),
                   (VarLocation{LocationType::kRegister, 56, {RegisterName::kR7}}));
#else
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 8, 8, 1, false),
                   (VarLocation{LocationType::kRegister, 0, {RegisterName::kRDI}}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 4, 4, 1, false),
                   (VarLocation{LocationType::kRegister, 8, {RegisterName::kRSI}}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 4, 4, 1, false),
                   (VarLocation{LocationType::kRegister, 16, {RegisterName::kRDX}}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 4, 4, 1, false),
                   (VarLocation{LocationType::kRegister, 24, {RegisterName::kRCX}}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 8, 4, 2, false),
                   (VarLocation{LocationType::kRegister, 32, {RegisterName::kR8}}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 8, 8, 1, false),
                   (VarLocation{LocationType::kRegister, 40, {RegisterName::kR9}}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 2, 2, 1, false),
                   (VarLocation{LocationType::kStack, 0}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 120, 8, 15, false),
                   (VarLocation{LocationType::kStack, 8}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 8, 8, 1, false),
                   (VarLocation{LocationType::kStack, 128}));
#endif
}

// Floating-point arguments use a separate register file that the fix also ported to
// arm64 (amd64 XMM0..XMM14 / arm64 V0..V15 for Go; XMM0..XMM7 / V0..V7 for the C ABI).
// These land with loc_type kRegisterFP. Exercise the first four FP args on both arches.
TEST(GolangRegisterABIModel, FloatParameters) {
  std::unique_ptr<ABICallingConventionModel> abi_model =
      ABICallingConventionModel::Create(ABI::kGolangRegister);
#if defined(__aarch64__)
  const RegisterName f0 = RegisterName::kV0, f1 = RegisterName::kV1, f2 = RegisterName::kV2,
                     f3 = RegisterName::kV3;
#else
  const RegisterName f0 = RegisterName::kXMM0, f1 = RegisterName::kXMM1, f2 = RegisterName::kXMM2,
                     f3 = RegisterName::kXMM3;
#endif
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kFloat, 8, 8, 1, false),
                   (VarLocation{LocationType::kRegisterFP, 0, {f0}}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kFloat, 4, 4, 1, false),
                   (VarLocation{LocationType::kRegisterFP, 8, {f1}}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kFloat, 8, 8, 1, false),
                   (VarLocation{LocationType::kRegisterFP, 16, {f2}}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kFloat, 8, 8, 1, false),
                   (VarLocation{LocationType::kRegisterFP, 24, {f3}}));
}

TEST(SystemVAMD64ABIModel, FloatParameters) {
  std::unique_ptr<ABICallingConventionModel> abi_model =
      ABICallingConventionModel::Create(ABI::kSystemVAMD64);
#if defined(__aarch64__)
  const RegisterName f0 = RegisterName::kV0, f1 = RegisterName::kV1, f2 = RegisterName::kV2,
                     f3 = RegisterName::kV3;
#else
  const RegisterName f0 = RegisterName::kXMM0, f1 = RegisterName::kXMM1, f2 = RegisterName::kXMM2,
                     f3 = RegisterName::kXMM3;
#endif
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kFloat, 8, 8, 1, false),
                   (VarLocation{LocationType::kRegisterFP, 0, {f0}}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kFloat, 4, 4, 1, false),
                   (VarLocation{LocationType::kRegisterFP, 8, {f1}}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kFloat, 8, 8, 1, false),
                   (VarLocation{LocationType::kRegisterFP, 16, {f2}}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kFloat, 8, 8, 1, false),
                   (VarLocation{LocationType::kRegisterFP, 24, {f3}}));
}

// Return values use the retval register tables (is_ret_arg=true), which the fix also
// ported to arm64. Go returns in the same registers as args (R0.. / RAX..).
TEST(GolangRegisterABIModel, ReturnValues) {
  std::unique_ptr<ABICallingConventionModel> abi_model =
      ABICallingConventionModel::Create(ABI::kGolangRegister);
#if defined(__aarch64__)
  const RegisterName r0 = RegisterName::kR0, r1 = RegisterName::kR1, r2 = RegisterName::kR2;
#else
  const RegisterName r0 = RegisterName::kRAX, r1 = RegisterName::kRBX, r2 = RegisterName::kRCX;
#endif
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 8, 8, 1, /*is_ret_arg*/ true),
                   (VarLocation{LocationType::kRegister, 0, {r0}}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 8, 8, 1, true),
                   (VarLocation{LocationType::kRegister, 8, {r1}}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 8, 8, 1, true),
                   (VarLocation{LocationType::kRegister, 16, {r2}}));
}

// The C ABI has only two integer return registers (arm64 X0/X1, amd64 RAX/RDX). A third
// return slot overflows into the hidden-return-pointer branch, which consumes the first
// integer *argument* register (arm64 X0, amd64 RDI).
TEST(SystemVAMD64ABIModel, ReturnValues) {
  std::unique_ptr<ABICallingConventionModel> abi_model =
      ABICallingConventionModel::Create(ABI::kSystemVAMD64);
#if defined(__aarch64__)
  const RegisterName ret0 = RegisterName::kR0, ret1 = RegisterName::kR1,
                     hidden_arg0 = RegisterName::kR0;
#else
  const RegisterName ret0 = RegisterName::kRAX, ret1 = RegisterName::kRDX,
                     hidden_arg0 = RegisterName::kRDI;
#endif
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 8, 8, 1, true),
                   (VarLocation{LocationType::kRegister, 0, {ret0}}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 8, 8, 1, true),
                   (VarLocation{LocationType::kRegister, 8, {ret1}}));
  EXPECT_OK_AND_EQ(abi_model->PopLocation(TypeClass::kInteger, 8, 8, 1, true),
                   (VarLocation{LocationType::kRegister, 0, {hidden_arg0}}));
}

// Regression: a System V function that uses up every integer argument register
// and then returns an aggregate larger than the integer return registers takes
// the hidden-return-pointer path. That path used to call
// int_arg_registers_.front()/pop_front() unconditionally, which is undefined
// behavior once the argument-register deque is empty. It must now yield a
// well-defined location instead of reading an empty deque. (Consume 8 integer
// args so the arg registers are exhausted on both System V (6) and AAPCS64 (8).)
TEST(SystemVAMD64ABIModel, ReturnValueAfterArgRegistersExhausted) {
  std::unique_ptr<ABICallingConventionModel> abi_model =
      ABICallingConventionModel::Create(ABI::kSystemVAMD64);
  for (int i = 0; i < 8; ++i) {
    EXPECT_OK(abi_model->PopLocation(TypeClass::kInteger, 8, 8, 1, /* is_ret_arg */ false));
  }
  // 24 bytes => 3 integer registers required > the 2 integer return registers,
  // so this hits the hidden-return-pointer branch with the arg registers empty.
  auto ret = abi_model->PopLocation(TypeClass::kInteger, 24, 8, 1, /* is_ret_arg */ true);
  EXPECT_OK(ret);
  EXPECT_EQ(ret.ConsumeValueOrDie().loc_type, LocationType::kStack);
}

}  // namespace obj_tools
}  // namespace stirling
}  // namespace px
