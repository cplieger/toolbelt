# Third-party notices

No third-party code is included in this repository. Two upstream projects were followed
closely enough to name their authors here, each beside the line of this code that follows
it. No license text is reproduced, because nothing was copied.

## houseabsolute/ubi

<https://github.com/houseabsolute/ubi>, MIT OR Apache-2.0.

`release.go` chooses one asset out of a forge release's file names in ubi's order:
installable extension first, then the single-candidate rule, then OS, then architecture.
The order is stated at `release.go:112-120` and runs at `release.go:131-165`. Ordering
architecture earlier lost 19 repositories on amd64 and 23 on arm64, and ubi's order
recovers them. The glibc-over-musl preference at `release.go:267-273` was settled by
checking what ubi does rather than by argument. ubi is Rust and this is Go, so no ubi
source was translated.

## aquaproj/aqua-registry

<https://github.com/aquaproj/aqua-registry>, MIT.

`aqua.go` implements the registry's package-definition schema, which is what lets the
catalog compiler unmarshal registry files directly. `AquaPackage` and its nested types
mirror the upstream field names (`aqua.go:24-95`; the schema is documented at
<https://aquaproj.github.io/docs/reference/registry-config>), `aquaTemplateFuncs` at
`aqua.go:140-152` provides the template helpers registry definitions reference, and the
extension-to-format table at `extract.go:40-42` follows the registry's documented rule
that an omitted format is inferred from the asset name's extension. Only the schema is
implemented; none of the registry's own definitions are in this repository.
