(use-modules (gnu packages rust))

;; Pure-Rust dependency tree: `rust` provides rustc, the linker, rustfmt and
;; clippy; `rust:cargo` provides cargo. Nothing else is needed to build, test,
;; format or lint enrichr.
(packages->manifest
 (list rust
       (list rust "cargo")))
