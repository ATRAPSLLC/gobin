//! Reading Go function names: the package a name belongs to, and the names
//! only a cgo binary holds.

/// Package path portion of a fully-qualified function name, or `None` if the
/// name has no package boundary. Mirrors
/// [`crate::metadata::FunctionInfo::package`] for callers that hold a bare
/// `&str`.
pub fn package_of(name: &str) -> Option<&str> {
    let boundary = package_boundary(name)?;
    name.get(..boundary)
}

/// Locate the package/short-name boundary in a Go function name.
///
/// Returns the byte index of the `.` that separates package path from the
/// trailing identifier(s). Both [`crate::metadata::FunctionInfo::package`]
/// and [`crate::metadata::FunctionInfo::short_name`] dispatch to this so they
/// always agree.
///
/// The base rule is "first `.` after the last `/`". Path segments use `/`
/// and identifiers do not, so this correctly distinguishes
/// `github.com/spf13/cobra.(*Command).Run` (package `github.com/spf13/cobra`)
/// from `runtime.gcStart` (package `runtime`).
///
/// On top of that we extend past `gopkg.in`-style `.vN` segments: a package
/// path like `gopkg.in/yaml.v3` ends with a `.vN` version that the base rule
/// would split incorrectly. If the segment immediately after the candidate
/// boundary matches `v<digits>.`, the boundary moves to the next `.`.
pub fn package_boundary(name: &str) -> Option<usize> {
    let last_slash = name.rfind('/').and_then(|p| p.checked_add(1)).unwrap_or(0);
    let segment = name.get(last_slash..)?;
    let first_dot = segment.find('.')?;
    let mut boundary = last_slash.checked_add(first_dot)?;

    let after_start = boundary.checked_add(1)?;
    if let Some(after) = name.get(after_start..)
        && let Some(rest) = after.strip_prefix('v')
    {
        let digit_end = rest.bytes().take_while(|b| b.is_ascii_digit()).count();
        if digit_end > 0 && rest.as_bytes().get(digit_end) == Some(&b'.') {
            // boundary advances by '.' + 'v' + N digits = 2 + digit_end
            boundary = boundary.checked_add(2)?.checked_add(digit_end)?;
        }
    }
    Some(boundary)
}

/// A stub cgo generates to call a C function: `pkg._Cfunc_<name>`.
pub fn is_cgo_stub(name: &str) -> bool {
    package_of(name)
        .and_then(|pkg| name.get(pkg.len()..))
        .is_some_and(|rest| rest.starts_with("._Cfunc_"))
}

/// Whether the function named `name` exists only in a binary that links
/// `runtime/cgo`: a C-call stub, the runtime's exports to the C side
/// (`_cgo_panic`, `_cgo_topofstack`) or its cgo pointer check.
pub fn is_cgo_marker(name: &str) -> bool {
    is_cgo_stub(name)
        || matches!(
            name,
            "_cgo_panic" | "_cgo_topofstack" | "runtime.cgoCheckPointer"
        )
}
