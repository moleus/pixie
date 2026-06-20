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

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.instrument.Instrumentation;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;

/**
 * Pixie JSSE agent — zero-broker-modification capture of JVM TLS plaintext.
 *
 * <p>Attach with {@code -javaagent:pixie-jsse-agent.jar=<path-to-libpixie_jsse.so>}.
 * Nothing in the broker is changed; the agent is injected through the JVM's standard
 * instrumentation entry point, exactly like an APM agent.
 *
 * <h3>Modes ({@code -Dpixie.jsse.mode=...})</h3>
 * <ul>
 *   <li><b>kafka</b> (default): instrument only
 *       {@code org.apache.kafka.common.network.SslTransportLayer}, which holds both
 *       the {@code SSLEngine} (plaintext) and the {@code SocketChannel} (the OS fd).
 *       Precise fd, no JDK internals touched — the proven path.</li>
 *   <li><b>engine</b>: the GENERIC hook — instrument {@code sun.security.ssl.SSLEngineImpl}
 *       {@code wrap/unwrap} (plaintext) for ANY JSSE user (Netty, gRPC-netty, plain
 *       NIO, …). An {@code SSLEngine} has no socket, so the fd is recovered from a
 *       thread-local set when the same thread does
 *       {@code sun.nio.ch.SocketChannelImpl.read/write} (the NIO event-loop pattern).
 *       Requires putting the agent on the bootstrap classloader to instrument
 *       {@code java.base}.</li>
 *   <li><b>both</b>: kafka + engine, with the engine hook deduplicating against the
 *       Kafka transport hook (see {@link EngineContext#inTransport}).</li>
 * </ul>
 * Only the generic modes touch {@code java.base}; the default stays minimal and safe.
 */
public final class PixieJsseAgent {
  private static final String KAFKA_TRANSPORT = "org.apache.kafka.common.network.SslTransportLayer";
  private static final String SSL_ENGINE_IMPL = "sun.security.ssl.SSLEngineImpl";
  private static final String SOCKET_CHANNEL_IMPL = "sun.nio.ch.SocketChannelImpl";

  private PixieJsseAgent() {}

  public static void premain(String args, Instrumentation inst) {
    install(args, inst);
  }

  public static void agentmain(String args, Instrumentation inst) {
    install(args, inst);
  }

  private static synchronized void install(String args, Instrumentation inst) {
    try {
      String mode = System.getProperty("pixie.jsse.mode", "kafka").toLowerCase();
      boolean kafka = mode.equals("kafka") || mode.equals("both");
      boolean engine = mode.equals("engine") || mode.equals("both");

      // The generic (SSLEngine) hook instruments java.base classes; their inlined
      // advice references our helper classes, which must therefore be visible to the
      // bootstrap classloader. Do this FIRST so all helper references resolve to the
      // single bootstrap copy (parent-first delegation) — one set of static state.
      if (engine) {
        injectHelpersIntoBootstrap(inst);
      }

      openJavaBasePackages(inst);

      String libPath = (args != null && !args.isEmpty()) ? args : System.getenv("PIXIE_JSSE_LIB");
      NativeBridge.init(libPath);
      log("native bridge loaded (ready=" + NativeBridge.isReady() + ") lib=" + libPath
          + " mode=" + mode);

      AgentBuilder b =
          new AgentBuilder.Default()
              // disableClassFormatChanges() selects the REDEFINE type strategy (no added
              // methods/fields), which is REQUIRED to retransform ALREADY-LOADED classes. Without
              // it ByteBuddy rebases (adds methods) and the JVM rejects the JVMTI retransform of a
              // loaded class, so a dynamic attach (e.g. the PEM/jattach injecting us into a running
              // broker) "installs" but instruments nothing. Our hooks are Advice-only (inlined into
              // existing method bodies), so REDEFINE is sufficient — and this also works at premain.
              .disableClassFormatChanges()
              .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
              .ignore(net.bytebuddy.matcher.ElementMatchers.none());

      if (kafka) {
        b =
            b.type(named(KAFKA_TRANSPORT))
                .transform(
                    (builder, td, cl, module, pd) ->
                        builder
                            .visit(
                                Advice.to(SslTransportLayerAdvice.Write.class)
                                    .on(named("write").and(takesArguments(1))
                                        .and(takesArgument(0, ByteBuffer.class))))
                            .visit(
                                Advice.to(SslTransportLayerAdvice.Read.class)
                                    .on(named("read").and(takesArguments(1))
                                        .and(takesArgument(0, ByteBuffer.class)))));
      }

      if (engine) {
        b =
            b.type(named(SSL_ENGINE_IMPL))
                .transform(
                    (builder, td, cl, module, pd) ->
                        builder
                            .visit(
                                Advice.to(SSLEngineAdvice.Wrap.class)
                                    .on(named("wrap").and(takesArguments(4))
                                        .and(takesArgument(0, ByteBuffer[].class))))
                            .visit(
                                Advice.to(SSLEngineAdvice.Unwrap.class)
                                    .on(named("unwrap").and(takesArguments(4))
                                        .and(takesArgument(1, ByteBuffer[].class)))))
                .type(named(SOCKET_CHANNEL_IMPL))
                .transform(
                    (builder, td, cl, module, pd) ->
                        builder
                            .visit(
                                Advice.to(SocketChannelFdAdvice.class)
                                    .on((named("read").or(named("write")))
                                        .and(takesArgument(0, ByteBuffer.class)))));
      }

      b.installOn(inst);
      log("instrumentation installed (kafka=" + kafka + ", engine=" + engine + ")");
    } catch (Throwable t) {
      log("FAILED to install: " + t);
      t.printStackTrace();
    }
  }

  // The ONLY classes that the advice woven into java.base actually calls at
  // runtime. Everything else (PixieJsseAgent, the advice classes, and all of
  // ByteBuddy) stays on the app/system loader.
  private static final String[] BOOTSTRAP_HELPERS = {
    "io/pixie/jsse/NativeBridge",
    "io/pixie/jsse/FdExtractor",
    "io/pixie/jsse/EngineContext",
    "io/pixie/jsse/PixieCapture",
  };

  /**
   * Put ONLY the small runtime helper classes onto the bootstrap classloader so
   * advice woven into {@code java.base} can resolve them.
   *
   * <p>The obvious approach — appending the whole shaded agent jar to bootstrap —
   * is the trap: it duplicates ByteBuddy on BOTH the app and bootstrap loaders, so
   * the first {@code AgentBuilder} call from {@code PixieJsseAgent} (app loader)
   * blows up with a {@code LinkageError: loader constraint violation} because the
   * two loaders disagree on the {@code ElementMatcher} type. We instead build a
   * tiny jar containing just the four helpers and append that. Parent-first
   * delegation then makes every reference to these classes — whether from
   * java.base-woven advice or app-loaded (Kafka) advice — resolve to the single
   * bootstrap copy, so there is exactly one set of static state and no duplication.
   */
  private static void injectHelpersIntoBootstrap(Instrumentation inst) {
    try {
      ClassLoader cl = PixieJsseAgent.class.getClassLoader();
      File jar = File.createTempFile("pixie-jsse-boot", ".jar");
      jar.deleteOnExit();
      try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(jar))) {
        byte[] buf = new byte[8192];
        for (String name : BOOTSTRAP_HELPERS) {
          String res = name + ".class";
          try (InputStream in = cl.getResourceAsStream(res)) {
            if (in == null) {
              log("WARN: bootstrap helper class not found on agent classpath: " + res);
              continue;
            }
            jos.putNextEntry(new JarEntry(res));
            int n;
            while ((n = in.read(buf)) > 0) {
              jos.write(buf, 0, n);
            }
            jos.closeEntry();
          }
        }
      }
      inst.appendToBootstrapClassLoaderSearch(new JarFile(jar));
      log("bootstrap helper jar appended (" + BOOTSTRAP_HELPERS.length + " classes): " + jar);
    } catch (Throwable t) {
      log("could not inject bootstrap helpers (engine mode may not work): " + t);
    }
  }

  /** Open the java.base packages we reflect into (sun.nio.ch, java.io) to whichever
   *  module(s) our helper classes ended up in (system unnamed in kafka mode,
   *  bootstrap unnamed in engine mode). */
  private static void openJavaBasePackages(Instrumentation inst) {
    try {
      Module base = Object.class.getModule();
      Set<Module> targets = new HashSet<>();
      targets.add(PixieJsseAgent.class.getModule());
      targets.add(FdExtractor.class.getModule());  // where setAccessible runs from
      targets.add(ClassLoader.getSystemClassLoader().getUnnamedModule());
      Map<String, Set<Module>> extraOpens = Map.of("sun.nio.ch", targets, "java.io", targets);
      inst.redefineModule(
          base, Collections.emptySet(), Collections.emptyMap(), extraOpens,
          Collections.emptySet(), Collections.emptyMap());
      log("opened java.base/{sun.nio.ch,java.io}");
    } catch (Throwable t) {
      log("could not redefineModule (fd extraction may need --add-opens): " + t);
    }
  }

  private static void log(String msg) {
    System.err.println("[pixie-jsse] " + msg);
  }
}
