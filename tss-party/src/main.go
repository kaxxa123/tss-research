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
)

const (
	DefaultPartySize = 6
	DefaultThreshold = 3
)

const (
	fixtureDirFormat    = "%s/tss_data/%d-of-%d"
	fixtureFileFormat   = "keygen_data_%d.json"
	fixtureFileWildcard = "keygen_data_*.json"
)

func clearFixtureDir(threshold, partySize int) error {
	_, callerFileName, _, _ := runtime.Caller(0)
	dirApp := filepath.Dir(callerFileName)
	dirOut := fmt.Sprintf(fixtureDirFormat, dirApp, threshold, partySize)
	filePattern := fmt.Sprintf("%s/%s", dirOut, fixtureFileWildcard)

	_, err := os.Stat(dirOut)
	if err != nil {
		if os.IsNotExist(err) {
			return nil;
		}
		return errors.Wrapf(err, "Error checking directory: %s", dirOut);
	}

	// Find files matching the pattern
	filePaths, err := filepath.Glob(filePattern)
	if err != nil {
		return errors.Wrapf(err, "Error finding files: %s", filePattern);
	}

	// Delete the files
	for _, filePath := range filePaths {
		err := os.Remove(filePath)
		if err != nil {
			return errors.Wrapf(err, "Error deleting file: %s", filePath);
		} 
		
		fmt.Println("File deleted:", filePath)
	}

	return nil;
}

func hasFixtureDir(threshold, partySize int) bool {
	_, callerFileName, _, _ := runtime.Caller(0)
	dirApp := filepath.Dir(callerFileName)
	dirOut := fmt.Sprintf(fixtureDirFormat, dirApp, threshold, partySize)

	di, err := os.Stat(dirOut)
	return err == nil && di.IsDir()
}

func createFixtureDir(threshold, partySize int) error {
	_, callerFileName, _, _ := runtime.Caller(0)
	dirApp := filepath.Dir(callerFileName)
	dirOut := fmt.Sprintf(fixtureDirFormat, dirApp, threshold, partySize)

	_, err := os.Stat(dirOut)
	if err != nil {

		if os.IsNotExist(err) {
			fmt.Println("Directory does not exist: ", dirOut)

			err = os.MkdirAll(dirOut, os.ModePerm)
			if err != nil {
				return errors.Wrapf(err, "Error creating directory: %s", dirOut)
			}
			fmt.Println("Directory created: ", dirOut)

		} else {
			return errors.Wrapf(err, "Error creating directory: %s", dirOut)
		}
	}

	return nil
}

// Detect the caller's path and derive the party's fixture filename.
func makeFixtureFilePath(threshold, partySize, partyIndex int) string {
	_, callerFileName, _, _ := runtime.Caller(0)
	dirApp := filepath.Dir(callerFileName)
	dirOut := fmt.Sprintf(fixtureDirFormat, dirApp, threshold, partySize)
	fileOut := fmt.Sprintf("%s/"+fixtureFileFormat, dirOut, partyIndex)
	fmt.Printf("File Path: %s\n", fileOut)
	return fileOut
}

func writeFixtureFile(threshold, partySize, partyIndex int, data keygen.LocalPartySaveData) error {

	fixtureFileName := makeFixtureFilePath(threshold, partySize, partyIndex)

	// If fixture file does not exist, create it
	fi, err := os.Stat(fixtureFileName)
	if err != nil ||
		fi == nil ||
		fi.IsDir() {

		fd, err := os.OpenFile(fixtureFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return errors.Wrapf(err, "Unable to open fixture file %s for writing", fixtureFileName)
		}

		bz, err := json.Marshal(&data)
		if err != nil {
			return errors.Wrapf(err, "Unable to marshal save data for fixture file %s", fixtureFileName)
		}

		_, err = fd.Write(bz)
		if err != nil {
			return errors.Wrapf(err, "Unable to write to fixture file %s", fixtureFileName)
		}

		fmt.Printf("Saved a test fixture file for party %d: %s\n", partyIndex, fixtureFileName)
	} else {
		fmt.Printf("Fixture file already exists for party %d; not re-creating: %s\n", partyIndex, fixtureFileName)
	}

	return nil;
}

func loadFixturesAll(threshold, partySize int, optionalStart ...int) ([]keygen.LocalPartySaveData, tss.SortedPartyIDs, error) {

	//Function requires the fixture dir to be already created
	if !hasFixtureDir(threshold, partySize) {
		return  nil, nil, fmt.Errorf("Fixture dir not found! Run Setup.")
	}

	keys := make([]keygen.LocalPartySaveData, 0, partySize)
	start := 0

	if len(optionalStart) > 0 {
		start = optionalStart[0]
	}

	for i := start; i < partySize; i++ {
		fixtureFilePath := makeFixtureFilePath(threshold, partySize, i)

		bz, err := ioutil.ReadFile(fixtureFilePath)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "Could not open fixture file for party %d located at: %s.", i, fixtureFilePath)
		}

		var key keygen.LocalPartySaveData
		if err = json.Unmarshal(bz, &key); err != nil {
			return nil, nil, errors.Wrapf(err, "Could not unmarshal fixture data for party %d located at: %s", i, fixtureFilePath)
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

// Randomly load (threshold+1) fixtures out of partySize
func loadFixturesSet(threshold, partySize int) ([]keygen.LocalPartySaveData, tss.SortedPartyIDs, error) {

	//Function requires the fixture dir to be already created
	if !hasFixtureDir(threshold, partySize) {
		return  nil, nil, fmt.Errorf("Fixture dir not found! Run Setup.")
	}

	qty	 := threshold + 1
	keys := make([]keygen.LocalPartySaveData, 0, qty)
	plucked := make(map[int]interface{}, qty)

	for i := 0; len(plucked) < qty; i = (i + 1) % partySize {
		_, have := plucked[i]
		if pluck := rand.Float32() < 0.5; !have && pluck {
			plucked[i] = new(struct{})
		}
	}

	for i := range plucked {
		fixtureFilePath := makeFixtureFilePath(threshold, partySize, i)

		bz, err := ioutil.ReadFile(fixtureFilePath)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "Could not open fixture file for party %d located at: %s.", i, fixtureFilePath)
		}

		var key keygen.LocalPartySaveData
		if err = json.Unmarshal(bz, &key); err != nil {
			return nil, nil, errors.Wrapf(err, "Could not unmarshal fixture data for party %d located at: %s", i, fixtureFilePath)
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

func distibutedKeyGeneration(threshold, partySize int) error {

	//Make sure the Fixtur dir exists
	err := createFixtureDir(threshold, partySize)
	if err != nil {
		return err
	}

	fmt.Println("Generating safe primes. This may take a while...")
	pIDs := tss.GenerateTestPartyIDs(partySize)

	p2pCtx  := tss.NewPeerContext(pIDs)
	parties := make([]*keygen.LocalParty, 0, len(pIDs))

	errCh := make(chan *tss.Error, len(pIDs))
	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan keygen.LocalPartySaveData, len(pIDs))

	updater := test.SharedPartyUpdater
	startGR := runtime.NumGoroutine()

	// init the parties
	for i := 0; i < len(pIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], len(pIDs), threshold)
		P := keygen.NewLocalParty(params, outCh, endCh).(*keygen.LocalParty)

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
			return err

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
					return fmt.Errorf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case save := <-endCh:
			// SAVE a test fixture file for this P (if it doesn't already exist)
			// .. here comes a workaround to recover this party's index (it was removed from save data)
			index, _ := save.OriginalIndex()
			err := writeFixtureFile(threshold, partySize, index, save)
			if err != nil {
				return err
			}

			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				fmt.Printf("Done. Received save data from %d participants\n", ended)
				fmt.Printf("Start goroutines: %d, End goroutines: %d\n", startGR, runtime.NumGoroutine())

				break keygen
			}
		}
	}

	return nil;
}

func distibutedSigning(threshold, partySize int) error {
	messageToSign := big.NewInt(42)

	keys, signPIDs, err := loadFixturesSet(threshold, partySize)
	if err != nil {
		return errors.Wrapf(err, "Failed to load keys.")
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
			return err

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
					return fmt.Errorf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case signReady := <-endCh:
			atomic.AddInt32(&signEnded, 1)
			if atomic.LoadInt32(&signEnded) == int32(len(signPIDs)) {
				fmt.Printf("Done. Received signature data from %d participants\n", signEnded)

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

				if !ok {
					return fmt.Errorf("ECDSA verification FAILED!")
				}

				fmt.Printf("ECDSA signing test done.\n")
				// END ECDSA verify

				break signing
			}
		}
	}

	return nil;
}

func usage() {
	fmt.Println("Usage: main <sub-command> [flags]")
	fmt.Println("\nSub-commands:")
	fmt.Println("  help  - Show this help info")
	fmt.Println("  setup - Perform signature setup")
	fmt.Println("  sign  - Sign random hash")
}

func flagsValidation(threshold, partySize int) (int, int) {

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

		flagsValidation(*setupThreshold, *setupParty)
		fmt.Println("Threshold:  ", *setupThreshold)
		fmt.Println("Party Size: ", *setupParty)

		err := clearFixtureDir(*setupThreshold, *setupParty)
		if err != nil {
			fmt.Println("Failed on clearing fixture dir.")
			fmt.Println(err)
			os.Exit(1)
		}

		err = distibutedKeyGeneration(*setupThreshold, *setupParty)
		if err != nil {
			fmt.Println("Setup failed.")
			fmt.Println(err)
			os.Exit(1)
		}

	case "sign":
		signCmd.Parse(os.Args[2:])
		fmt.Println("Signing...")

		flagsValidation(*signThreshold, *signParty)
		fmt.Println("Threshold:  ", *signThreshold)
		fmt.Println("Party Size: ", *signParty)

		err := distibutedSigning(*signThreshold, *signParty)
		if err != nil {
			fmt.Println("Signing failed.")
			fmt.Println(err)
			os.Exit(1)
		}

	case "help":
		usage()

	default:
		fmt.Printf("Unknown command '%s'\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}
