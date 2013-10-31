package bcryptplus

import (
	"code.google.com/p/go.crypto/bcrypt"
	"errors"
	"github.com/pavben/monoclock"
	"fmt"
)

// Errors
var (
	ErrMinHashTimeTooHigh = errors.New("bcryptplus: minHashTimeMillis too high")
	ErrSearchAllFalse = errors.New("bcryptplus: Predicate is false for all values in range")
)

// The main Hasher struct
type Hasher struct {
	currentCost int
	minHashTimeMillis int64
}

// Creates a new Hasher
//
// minHashTimeMillis specifies the minimum time (in milliseconds) that this Hasher will enforce for producing hashes.
// If hashing takes less than this minimum time, the hashing difficulty will be increased.
func NewHasher(minHashTimeMillis int64) (*Hasher, error) {
	cost, err := findFirstTrue(bcrypt.DefaultCost, bcrypt.MaxCost, predicateCostTimeFunction(minHashTimeMillis))

	if err != nil {
		if err == ErrSearchAllFalse {
			return nil, ErrMinHashTimeTooHigh
		} else {
			return nil, err
		}
	} else {
		return &Hasher {
			currentCost: cost,
			minHashTimeMillis: minHashTimeMillis,
		}, nil
	}
}

// Hashes the given password
func (self *Hasher) Hash(password []byte) ([]byte, error) {
	for {
		if (self.currentCost > bcrypt.MaxCost) {
			return nil, ErrMinHashTimeTooHigh
		}

		hash, timeMillis, err := hashAndTime(password, self.currentCost)

		if err != nil {
			return nil, err
		} else {
			// if it took long enough, break
			if timeMillis >= self.minHashTimeMillis {
				return hash, nil
			} else {
				fmt.Printf("hashing with currentCost %d was too fast: %dms\n", self.currentCost, timeMillis)
				// otherwise, increment the cost and try again
				self.currentCost++
			}
		}
	}
}

// Checks if the password matches the hash
//
// If the cost of the given hash is below the cost we currently use, the 2nd return value will contain a new and stronger hash.
// If the 2nd return value is present, you must update the hash for the password to it or you're missing out on the security benefits and wasting CPU cycles.
// If the given hash is already strong enough, the 2nd argument will be nil.
func (self *Hasher) Validate(password []byte, hash []byte) (bool, []byte, error) {
	err := bcrypt.CompareHashAndPassword(hash, password)

	if err != nil {
		// password and hash do not match
		return false, nil, nil
	} else {
		// password matches the hash

		costOfHash, err := bcrypt.Cost(hash)

		if err != nil || costOfHash < self.currentCost {
			// if unable to determine the cost (err != nil), treat it the same as an outdated hash

			newHash, err := self.Hash(password)

			if err != nil {
				return true, nil, err
			} else {
				return true, newHash, nil
			}
		} else {
			// the hash is valid and is sufficiently strong
			return true, nil, nil
		}
	}
}

// Returns the hash and the time in milliseconds that it took to hash
// Any error condition would come directly from bcrypt
func hashAndTime(password []byte, cost int) ([]byte, int64, error) {
	timer := monoclock.NewMonoTimer()

	hash, err := bcrypt.GenerateFromPassword(password, cost)

	if err != nil {
		return nil, -1, err
	} else {
		return hash, timer.Value(), nil
	}
}

// Returns the function which, given a hash cost, decides if the hashing time with that cost is high enough
func predicateCostTimeFunction(minHashTimeMillis int64) (func(cost int) (bool, error)) {
	return func(cost int) (bool, error) {
		timeMillis, err := estimateTimeForCost(cost)

		if err != nil {
			return false, err
		} else {
			return timeMillis >= minHashTimeMillis, nil
		}
	}
}

// Given a cost, returns an estimate of how long the hashing takes in milliseconds
func estimateTimeForCost(cost int) (int64, error) {
	_, timeMillis, err := hashAndTime([]byte("password"), cost)

	if err != nil {
		return -1, err
	} else {
		return timeMillis, nil
	}
}

func findFirstTrue(lo, hi int, p func(int) (bool, error)) (int, error) {
	// TODO: consider the modified binary search instead of linear for a potentially faster init

	for i := lo; i <= hi; i++ {
		isTrue, err := p(i)

		if err != nil {
			return -1, err
		} else if isTrue {
			return i, nil
		}
	}

	return -1, ErrSearchAllFalse
}
