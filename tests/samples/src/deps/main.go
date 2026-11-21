// Command deps imports a module from the module cache and is built without
// -trimpath, so its source paths name GOROOT, the module cache and the
// build directory, as an ordinary `go build` in a user's home records them.
package main

import (
	"fmt"

	"example.com/greet"
)

func main() {
	fmt.Println(greet.Hello("deps"), greet.Shout("deps"))
}
