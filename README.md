A futureproof way of using bcrypt for hashing passwords. Specify the hash difficulty in milliseconds and bcryptplus will automatically select the hash difficulty to match the given time for your machine. As processing power continues to rise according to Moore's law, your password hashes will automatically keep up with the times.

#### Check out the GoDoc at https://godoc.org/github.com/pavben/bcryptplus

### FAQ

#### How secure is bcryptplus?

**bcryptplus** is a wrapper for http://code.google.com/p/go.crypto/bcrypt which dynamically determines the hashing cost. It will start at bcrypt's default cost (currently 10) and increase it as needed to meet your time requirement, so it will always be at least as secure as the library it wraps if the hashing cost is not explicitly raised.

#### How exactly do you measure the time that hashing takes?

**bcryptplus** uses a raw monotonic clock (not affected by time adjustments). See http://github.com/pavben/monoclock for details. This is why it's currently **Linux only**. Using a standard clock would have been a security risk.

#### How do I specify the hashing difficulty?

```go
// all hashes produced by this Hasher will take at least 300ms on your machine
hasher, err := bcryptplus.NewHasher(300)
```

## Detailed Example

```go
package main

import (
	"fmt"
	"github.com/pavben/bcryptplus"
)

func main() {
	// create a new Hasher
	hasher, err := bcryptplus.NewHasher(300)

	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}

	// hash the password
	password := []byte("password")

	hash, err := hasher.Hash(password)

	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}

	fmt.Printf("hash = %s\n", hash)

	// check if the password matches the hash
	isValid, newHash, err := hasher.Validate(password, hash)

	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}

	fmt.Printf("isValid = %v, newHash = %v, err = %v\n", isValid, newHash, err)
}
```
