pub const VERSION = "0.4.0";
pub const VERSION_MAJOR = 0;
pub const VERSION_MINOR = 4;
pub const VERSION_PATCH = 0;
pub const VERSION_STRING = "ZEVM v" ++ VERSION;
pub const RELEASE_DATE = "2026-03-06";

// Not wired: referencing any of these is a compile error.
pub const BUILD_DATE = @compileError("Build date should be set by build system");
pub const GIT_COMMIT = @compileError("Git commit should be set by build system");
pub const GIT_BRANCH = @compileError("Git branch should be set by build system");
