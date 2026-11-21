// Package greet is the module the deps fixture loads from the module cache,
// served by a local file proxy so the build needs no network.
package greet

//go:noinline
func Hello(name string) string { return "hello, " + name }

// Shout is a package-level function literal, which coverage names by its
// position.
var Shout = func(name string) string { return Hello(name) + "!" }
