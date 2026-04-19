//! Build script for `meshtastic-proto`.
//!
//! Compiles every `*.proto` file under `<repo-root>/protobufs/meshtastic/`
//! using `prost-build` and emits a single `meshtastic.rs` module under
//! `OUT_DIR`, which `lib.rs` then re-exports.
//!
//! The Meshtastic protos use the `nanopb` extension options (`nanopb.proto`
//! lives at the root of the `protobufs/` directory). We add the `protobufs/`
//! directory to the include path so `import "nanopb.proto";` resolves, and we
//! pass `nanopb.proto` to `prost-build` as well — `prost` will simply ignore
//! the unknown field options at codegen time, so we get clean Rust types
//! without any of the C-flavoured nanopb annotations.

use std::path::{Path, PathBuf};
use std::{env, fs, io};

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = <repo>/rust/crates/meshtastic-proto
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    manifest_dir
        .ancestors()
        .nth(3)
        .expect("repository root is three levels above the crate")
        .to_path_buf()
}

fn collect_protos(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("proto") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

fn main() -> io::Result<()> {
    let root = repo_root();
    let protobufs_dir = root.join("protobufs");
    let meshtastic_dir = protobufs_dir.join("meshtastic");

    if !meshtastic_dir.is_dir() {
        // Surface a clear, actionable error rather than letting `protoc` fail.
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "protobufs not found at {}.\n\
                 Initialise the submodule from the repo root:\n    \
                 git submodule update --init protobufs",
                meshtastic_dir.display()
            ),
        ));
    }

    let mut protos = collect_protos(&meshtastic_dir)?;
    // `nanopb.proto` is referenced by `meshtastic/deviceonly.proto`. Compile it
    // too so its (file-level) options don't cause a missing-symbol error;
    // `prost` ignores the actual `nanopb` extension fields.
    protos.push(protobufs_dir.join("nanopb.proto"));

    // Re-run codegen whenever any proto changes.
    println!("cargo:rerun-if-changed=build.rs");
    for p in &protos {
        println!("cargo:rerun-if-changed={}", p.display());
    }

    let mut config = prost_build::Config::new();
    config.protoc_arg("--experimental_allow_proto3_optional");

    if env::var_os("CARGO_FEATURE_SERDE").is_some() {
        config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
        config.type_attribute(".", "#[serde(rename_all = \"camelCase\")]");
    }

    config.compile_protos(&protos, &[protobufs_dir])?;
    Ok(())
}
