# Prebuilt pixie-jsse agent jar

`pixie-jsse-agent.jar` is the shaded Java agent (`../`, built with Maven + ByteBuddy), checked in
as a binary so it can be baked into the PEM image and injected into broker JVMs by `px_jattach`
with **no broker restart or config**.

Why committed instead of Bazel-built: Pixie's Bazel is hermetic and has no Maven path for the
ByteBuddy dependency. Building/shading the jar in Bazel (via `rules_jvm_external`, which is
present) is the cleaner long-term option but requires adding ByteBuddy to `maven_install` and
re-pinning — a follow-up. CI (`.github/workflows/java-tls-artifacts.yaml`) is the source of truth
and rebuilds this jar from source on every change.

## Regenerate after changing the agent
```
cd ..                              # the agent module (pom.xml)
mvn -B -ntp clean package
cp target/pixie-jsse-agent.jar prebuilt/pixie-jsse-agent.jar
```
The native `libpixie_jsse.so` is, by contrast, Bazel-built per-arch from `../../native`.
