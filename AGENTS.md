# Repository Guidelines

## Project Structure & Module Organization
- `src/` defines shared CMake targets, while production code lives under `server/src` and `client/src`.
- Public headers are split by side: `server/include` and `client/include`.
- Windows process-injection code lives in `server/modules/process_inject` and `client/modules/process_inject`.
- `tests/` is organized by subsystem (`logging/`, `network/`, `server/`, `performance/`).
- Runtime config lives in `config/clink.init.toml`; build outputs go to `Out/`; logs go to `logs/`; vendored dependencies live in `external/`.

## Build, Test, and Development Commands
- `cmake --preset debug` configures a Debug Ninja build in `build/debug`.
- `cmake --build --preset debug` builds the default debug targets; add `--target clink-cli clink-server` for faster iteration.
- `ctest --preset debug --output-on-failure` runs registered tests.
- `cmake -S . -B build/release -G Ninja -DCMAKE_BUILD_TYPE=Release -DCLINK_ENABLE_TESTS=OFF` creates a release build when presets are not suitable.
- Run locally with `./Out/clink-server --config ./config/clink.init.toml` and `./Out/clink-cli status` on Unix-like systems, or `.\Out\clink-server.exe --config .\config\clink.init.toml` on Windows.

## Coding Style & Naming Conventions
- Use C++20, 4-space indentation, and same-line braces; match the surrounding file before making broader style changes.
- Keep file names and module names in `snake_case` such as `session_manager.cpp` and `tls_adapter.hpp`.
- Prefer `PascalCase` for types and `camelCase` for functions and local variables.
- Keep changes warning-clean: `cmake/ProjectOptions.cmake` enables `-Wall`, `-Wextra`, `-Wpedantic`, and related checks.
- No repo-wide formatter is configured, so avoid unrelated reformatting.

## Testing Guidelines
- Add new tests under `tests/<area>/` and use the `*_test.cpp` naming pattern.
- Use Catch2 `TEST_CASE` blocks for unit and integration coverage.
- Keep long-running benchmarks in `tests/performance/`; they are built separately and are not registered with `ctest` by default.
- During development, prefer targeted runs such as `ctest --test-dir build/debug -R clink-network-tests-v2 --output-on-failure`.

## Commit & Pull Request Guidelines
- Follow the existing history: short, descriptive subjects, often in Chinese, focused on one change.
- Use version-only subjects like `v1.2.0` only for release bumps.
- Example style: `修复退出重复停机竞态，修复TCP异步路径`.
- Pull requests should summarize the affected subsystem, target platform (`Windows`, `Linux`, or both), config changes, and test evidence.
- Include console output or screenshots when CLI behavior changes.

## Security & Configuration Tips
- Do not commit secrets, certificates, or generated artifacts from `Out/`, `logs/`, or `config/certs/`.
- Prefer `CLINK_CONFIG_PATH` for local configuration overrides.
- Keep Windows and WSL/Linux build directories separate to avoid cross-platform build contamination.
