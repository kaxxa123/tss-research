package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync/atomic"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/test"
	"github.com/bnb-chain/tss-lib/tss"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

const (
	DefaultPartySize = 6
	DefaultThreshold = 3
)

const (
	testFixtureDirFormat    = "%s/tss_data"
	testFixtureFileFormat   = "keygen_data_%d.json"
	testFixtureFileWildcard = "keygen_data_*.json"
)

func clearFixtureDir() {
	_, callerFileName, _, _ := runtime.Caller(0)
	dirApp := filepath.Dir(callerFileName)
	dirOut := fmt.Sprintf(testFixtureDirFormat, dirApp)
	filePattern := fmt.Sprintf("%s/%s", dirOut, testFixtureFileWildcard)

	_, err := os.Stat(dirOut)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}

		fmt.Println("Error checking directory: ", err)
		os.Exit(1)
	}

	// Find files matching the pattern
	filePaths, err := filepath.Glob(filePattern)
	if err != nil {
		fmt.Println("Error finding files:", err)
		os.Exit(1)
	}

	// Delete the files
	for _, filePath := range filePaths {
		err := os.Remove(filePath)
		if err != nil {
			fmt.Println("Error deleting file:", err)
			os.Exit(1)
		} else {
			fmt.Println("File deleted:", filePath)
		}
	}
}

func createFixtureDir() string {
	_, callerFileName, _, _ := runtime.Caller(0)
	dirApp := filepath.Dir(callerFileName)
	dirOut := fmt.Sprintf(testFixtureDirFormat, dirApp)

	_, err := os.Stat(dirOut)
	if err != nil {

		if os.IsNotExist(err) {
			fmt.Println("Directory does not exist: ", dirOut)

			err = os.MkdirAll(dirOut, os.ModePerm)
			if err != nil {
				fmt.Println("Error creating directory: ", err)
				os.Exit(1)
			}
			fmt.Println("Directory created: ", dirOut)

		} else {
			fmt.Println("Error checking directory: ", err)
			os.Exit(1)
		}
	}

	return dirOut
}

// Detect the caller's path and derive the party's fixture filename.
func makeTestFixtureFilePath(partyIndex int) string {
	dirOut := createFixtureDir()
	fileOut := fmt.Sprintf("%s/"+testFixtureFileFormat, dirOut, partyIndex)

	fmt.Printf("File Path: %s\n", fileOut)
	return fileOut
}

func tryWriteTestFixtureFile(index int, data keygen.LocalPartySaveData) bool {

	fixtureFileName := makeTestFixtureFilePath(index)

	// If fixture file does not exist, create it
	fi, err := os.Stat(fixtureFileName)
	if err != nil ||
		fi == nil ||
		fi.IsDir() {

		fd, err := os.OpenFile(fixtureFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			fmt.Errorf("Unable to open fixture file %s for writing", fixtureFileName)
			return false
		}

		bz, err := json.Marshal(&data)
		if err != nil {
			fmt.Errorf("Unable to marshal save data for fixture file %s", fixtureFileName)
			return false
		}

		_, err = fd.Write(bz)
		if err != nil {
			fmt.Errorf("Unable to write to fixture file %s", fixtureFileName)
			return false
		}

		fmt.Printf("Saved a test fixture file for party %d: %s\n", index, fixtureFileName)
	} else {
		fmt.Printf("Fixture file already exists for party %d; not re-creating: %s\n", index, fixtureFileName)
	}

	return true
}

func LoadKeygenTestFixtures(qtyParticipants int, optionalStart ...int) ([]keygen.LocalPartySaveData, tss.SortedPartyIDs, error) {

	keys := make([]keygen.LocalPartySaveData, 0, qtyParticipants)
	start := 0

	if len(optionalStart) > 0 {
		start = optionalStart[0]
	}

	for i := start; i < qtyParticipants; i++ {
		fixtureFilePath := makeTestFixtureFilePath(i)
		bz, err := ioutil.ReadFile(fixtureFilePath)
		if err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not open the test fixture for party %d in the expected location: %s. run keygen tests first.",
				i, fixtureFilePath)
		}

		var key keygen.LocalPartySaveData
		if err = json.Unmarshal(bz, &key); err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not unmarshal fixture data for party %d located at: %s",
				i, fixtureFilePath)
		}

		for _, kbxj := range key.BigXj {
			kbxj.SetCurve(tss.S256())
		}

		key.ECDSAPub.SetCurve(tss.S256())
		keys = append(keys, key)
	}

	partyIDs := make(tss.UnSortedPartyIDs, len(keys))
	for i, key := range keys {
		pMoniker := fmt.Sprintf("%d", i+start+1)
		partyIDs[i] = tss.NewPartyID(pMoniker, pMoniker, key.ShareID)
	}

	sortedPIDs := tss.SortPartyIDs(partyIDs)
	return keys, sortedPIDs, nil
}

// Randomly load qty of fixtures out of fixtureCount
func LoadKeygenTestFixturesRandomSet(qty, fixtureCount int) ([]keygen.LocalPartySaveData, tss.SortedPartyIDs, error) {

	keys := make([]keygen.LocalPartySaveData, 0, qty)
	plucked := make(map[int]interface{}, qty)

	for i := 0; len(plucked) < qty; i = (i + 1) % fixtureCount {
		_, have := plucked[i]
		if pluck := rand.Float32() < 0.5; !have && pluck {
			plucked[i] = new(struct{})
		}
	}

	for i := range plucked {
		fixtureFilePath := makeTestFixtureFilePath(i)
		bz, err := ioutil.ReadFile(fixtureFilePath)

		if err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not open the test fixture for party %d in the expected location: %s. run keygen tests first.",
				i, fixtureFilePath)
		}

		var key keygen.LocalPartySaveData
		if err = json.Unmarshal(bz, &key); err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not unmarshal fixture data for party %d located at: %s",
				i, fixtureFilePath)
		}

		for _, kbxj := range key.BigXj {
			kbxj.SetCurve(tss.S256())
		}

		key.ECDSAPub.SetCurve(tss.S256())
		keys = append(keys, key)
	}

	partyIDs := make(tss.UnSortedPartyIDs, len(keys))
	j := 0

	for i := range plucked {
		key := keys[j]
		pMoniker := fmt.Sprintf("%d", i+1)
		partyIDs[j] = tss.NewPartyID(pMoniker, pMoniker, key.ShareID)
		j++
	}

	sortedPIDs := tss.SortPartyIDs(partyIDs)
	sort.Slice(keys, func(i, j int) bool { return keys[i].ShareID.Cmp(keys[j].ShareID) == -1 })

	return keys, sortedPIDs, nil
}

func testDistibutedKeyGeneration(threshold, partySize int) {
	fixtures, pIDs, err := LoadKeygenTestFixtures(partySize)
	if err != nil {
		common.Logger.Info("No fixtures found, generating safe primes. This may take a while...")
		pIDs = tss.GenerateTestPartyIDs(partySize)
	}

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*keygen.LocalParty, 0, len(pIDs))

	errCh := make(chan *tss.Error, len(pIDs))
	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan keygen.LocalPartySaveData, len(pIDs))

	updater := test.SharedPartyUpdater
	startGR := runtime.NumGoroutine()

	// init the parties
	for i := 0; i < len(pIDs); i++ {
		var P *keygen.LocalParty

		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], len(pIDs), threshold)
		if i < len(fixtures) {
			P = keygen.NewLocalParty(params, outCh, endCh, fixtures[i].LocalPreParams).(*keygen.LocalParty)
		} else {
			P = keygen.NewLocalParty(params, outCh, endCh).(*keygen.LocalParty)
		}

		parties = append(parties, P)
		go func(P *keygen.LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	// PHASE: keygen
	var ended int32
keygen:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			break keygen

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil { // broadcast!
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else { // point-to-point!
				if dest[0].Index == msg.GetFrom().Index {
					fmt.Errorf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
					return
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case save := <-endCh:
			// SAVE a test fixture file for this P (if it doesn't already exist)
			// .. here comes a workaround to recover this party's index (it was removed from save data)
			index, _ := save.OriginalIndex()
			tryWriteTestFixtureFile(index, save)

			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				fmt.Printf("Done. Received save data from %d participants\n", ended)
				fmt.Printf("Start goroutines: %d, End goroutines: %d\n", startGR, runtime.NumGoroutine())

				break keygen
			}
		}
	}
}

func testDistibutedSigning(threshold, partySize int) {
	messageToSign := big.NewInt(42)

	keys, signPIDs, err := LoadKeygenTestFixturesRandomSet(threshold+1, partySize)
	if err != nil {
		common.Logger.Error("should load keygen fixtures")
	}

	// PHASE: signing
	// use a shuffled selection of the list of parties for this test
	// init the parties
	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*signing.LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold)

		P := signing.NewLocalParty(messageToSign, params, keys[i], outCh, endCh).(*signing.LocalParty)
		parties = append(parties, P)
		go func(P *signing.LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var signEnded int32
signing:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(nil, err.Error())
			break signing

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					common.Logger.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case signReady := <-endCh:
			atomic.AddInt32(&signEnded, 1)
			if atomic.LoadInt32(&signEnded) == int32(len(signPIDs)) {
				common.Logger.Debug("Done. Received signature data from %d participants", signEnded)

				// BEGIN ECDSA verify
				pkX, pkY := keys[0].ECDSAPub.X(), keys[0].ECDSAPub.Y()
				pk := ecdsa.PublicKey{
					Curve: tss.EC(),
					X:     pkX,
					Y:     pkY,
				}
				ok := ecdsa.Verify(&pk, messageToSign.Bytes(),
					new(big.Int).SetBytes(signReady.R),
					new(big.Int).SetBytes(signReady.S))

				assert.True(nil, ok, "ecdsa verify must pass")
				fmt.Printf("ECDSA signing test done.\n")
				// END ECDSA verify
				break signing
			}
		}
	}
}

func usage() {
	fmt.Println("Usage: main <sub-command> [flags]")
	fmt.Println("\nSub-commands:")
	fmt.Println("  help  - Show this help info")
	fmt.Println("  setup - Perform signature setup")
	fmt.Println("  sign  - Sign random hash")
}

func flagsNormalize(threshold, partySize int) (int, int) {

	if threshold < 0 {
		fmt.Printf("Invalid flags, threshold (%d) must be greater or equal to zero.\n", threshold)
		os.Exit(1)
	}

	if threshold >= partySize {
		fmt.Printf("Invalid flags, threshold (%d) must be smaller than the party size (%d).\n", threshold, partySize)
		os.Exit(1)
	}

	return threshold, partySize
}

func main() {

	setupCmd := flag.NewFlagSet("setup", flag.ExitOnError)
	setupThreshold := setupCmd.Int("threshold", DefaultThreshold, "Signer threshold")
	setupParty := setupCmd.Int("party", DefaultPartySize, "Number of Participants")

	signCmd := flag.NewFlagSet("sign", flag.ExitOnError)
	signThreshold := signCmd.Int("threshold", DefaultThreshold, "Signer threshold")
	signParty := signCmd.Int("party", DefaultPartySize, "Number of Participants")

	// Parse the command-line arguments
	if len(os.Args) < 2 {
		fmt.Println("Please specify a command (setup or sign)")
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "setup":
		setupCmd.Parse(os.Args[2:])
		fmt.Println("Setup...")

		*setupThreshold, *setupParty = flagsNormalize(*setupThreshold, *setupParty)
		fmt.Println("Threshold:  ", *setupThreshold)
		fmt.Println("Party Size: ", *setupParty)
		clearFixtureDir()
		testDistibutedKeyGeneration(*setupThreshold, *setupParty)

	case "sign":
		signCmd.Parse(os.Args[2:])
		fmt.Println("Signing...")

		*signThreshold, *signParty = flagsNormalize(*signThreshold, *signParty)
		fmt.Println("Threshold:  ", *signThreshold)
		fmt.Println("Party Size: ", *signParty)
		testDistibutedSigning(*signThreshold, *signParty)

	case "help":
		usage()

	default:
		fmt.Printf("Unknown command '%s'\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}
