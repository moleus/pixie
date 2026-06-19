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
package io.pixie.jsse;

import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.takesArgument;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

import java.lang.instrument.Instrumentation;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;

/**
 * Pixie JSSE agent — zero-broker-modification capture of Kafka TLS plaintext.
 *
 * <p>Attach with {@code -javaagent:pixie-jsse-agent.jar=<path-to-libpixie_jsse.so>}
 * (or set the lib path via the {@code PIXIE_JSSE_LIB} env var). Nothing in the
 * Kafka distribution is changed; the agent is injected through the JVM's
 * standard instrumentation entry point, exactly like an APM agent.
 *
 * <p>What it does at startup:
 * <ol>
 *   <li>Opens the encapsulated {@code java.base} packages it needs (sun.nio.ch,
 *       java.io) to the agent module, so fd extraction works without any
 *       {@code --add-opens} flags on the command line.</li>
 *   <li>Loads the native bridge library (the eBPF uprobe target).</li>
 *   <li>Weaves capture advice into {@code SslTransportLayer.read/write}.</li>
 * </ol>
 */
public final class PixieJsseAgent {
  private static final String TARGET = "org.apache.kafka.common.network.SslTransportLayer";

  private PixieJsseAgent() {}

  public static void premain(String args, Instrumentation inst) {
    install(args, inst);
  }

  public static void agentmain(String args, Instrumentation inst) {
    install(args, inst);
  }

  private static synchronized void install(String args, Instrumentation inst) {
    try {
      openJavaBasePackages(inst);

      String libPath = (args != null && !args.isEmpty()) ? args : System.getenv("PIXIE_JSSE_LIB");
      NativeBridge.init(libPath);
      log("native bridge loaded (ready=" + NativeBridge.isReady() + ") lib=" + libPath);

      new AgentBuilder.Default()
          .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
          .ignore(net.bytebuddy.matcher.ElementMatchers.none())
          .type(named(TARGET))
          .transform(
              (builder, typeDescription, classLoader, module, pd) ->
                  builder
                      .visit(
                          Advice.to(SslTransportLayerAdvice.Write.class)
                              .on(named("write").and(takesArguments(1)).and(takesArgument(0, ByteBuffer.class))))
                      .visit(
                          Advice.to(SslTransportLayerAdvice.Read.class)
                              .on(named("read").and(takesArguments(1)).and(takesArgument(0, ByteBuffer.class)))))
          .installOn(inst);

      log("instrumentation installed on " + TARGET);
    } catch (Throwable t) {
      log("FAILED to install: " + t);
      t.printStackTrace();
    }
  }

  /** Open the java.base packages we reflect into, to this agent's module. */
  private static void openJavaBasePackages(Instrumentation inst) {
    try {
      Module base = Object.class.getModule();
      Module agent = PixieJsseAgent.class.getModule();
      Map<String, Set<Module>> extraOpens =
          Map.of("sun.nio.ch", Set.of(agent), "java.io", Set.of(agent));
      inst.redefineModule(
          base,
          Collections.emptySet(),       // extraReads
          Collections.emptyMap(),       // extraExports
          extraOpens,                   // extraOpens
          Collections.emptySet(),       // extraUses
          Collections.emptyMap());      // extraProvides
      log("opened java.base/{sun.nio.ch,java.io} to agent module");
    } catch (Throwable t) {
      log("could not redefineModule (fd extraction may need --add-opens): " + t);
    }
  }

  private static void log(String msg) {
    System.err.println("[pixie-jsse] " + msg);
  }
}
