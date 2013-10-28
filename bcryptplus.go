package bcryptplus

import (
	"code.google.com/p/go.crypto/bcrypt"
	"errors"
	"time"
	"fmt"
)

var ErrNotInitialized = errors.New("bcryptplus: Call bcryptplus.Init(minHashTime) first")

var ErrMinHashTimeTooHigh = errors.New("bcryptplus: minHashTime too high")

var ErrSearchAllFalse = errors.New("bcryptplus: Predicate is false for all values in range")

type Hasher struct {
	currentCost int
	minHashTime int
}

func NewHasher(minHashTime int) (*Hasher, error) {
	fmt.Printf("%d", MaxInt)

	cost, err := findFirstTrue(bcrypt.DefaultCost, bcrypt.MaxCost, predicateCostTimeFunction(minHashTime))

	if err != nil {
		if err == ErrSearchAllFalse {
			return nil, ErrMinHashTimeTooHigh
		} else {
			return nil, err
		}
	} else {
		return &Hasher {
			currentCost: cost,
			minHashTime: minHashTime,
		}, nil
	}
}

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
			if timeMillis >= self.minHashTime {
				return hash, nil
			} else {
				fmt.Printf("hashing with currentCost %d was too fast: %dms\n", self.currentCost, timeMillis)
				// otherwise, increment the cost and try again
				self.currentCost++
			}
		}
	}
}

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

func hashAndTime(password []byte, cost int) ([]byte, int64, error) {
	startTime := time.Now()

	hash, err := bcrypt.GenerateFromPassword(password, cost)

	if err != nil {
		return nil, -1, err
	} else {
		duration := time.Since(startTime)

		return hash, int64(duration / time.Millisecond), nil
	}
}

func predicateCostTimeFunction(minHashTime int) (func(cost int) (bool, error)) {
	return func(cost int) (bool, error) {
		timeMillis, err := estimateTimeForCost(cost)

		if err != nil {
			return false, err
		} else {
			fmt.Printf("hashing took %dms\n", timeMillis)
			return timeMillis >= minHashTime, nil
		}
	}
}

func estimateTimeForCost(cost int) (int, error) {
	_, timeMillis, err := hashAndTime([]byte("password"), cost)

	if err != nil {
		return -1, err
	} else {
		return timeMillis, nil
	}
}

func findFirstTrue(lo, hi int, p func(int) (bool, error)) (int, error) {
	// TODO: consider the modified binary search instead of linear

	for i := lo; i <= hi; i++ {
		fmt.Printf("trying %d\n", i)
		isTrue, err := p(i)

		if err != nil {
			return -1, err
		} else if isTrue {
			return i, nil
		}
	}

	return -1, ErrSearchAllFalse
}
