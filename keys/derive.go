// Copyright © 2017-2018 The IPFN Developers. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package keys

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	cmdutil "github.com/ipfn/go-ipfn-cmd-util"
	"github.com/ipfn/go-ipfn-cmd-util/logger"
	keywallet "github.com/ipfn/go-ipfn-keywallet"
	pkhash "github.com/ipfn/go-ipfn-pkhash"
)

var (
	bechAddr      bool
	btcAddr       bool
	printKey      bool
	hashPath      bool
	customSeedPwd bool
	keyAddrID     string
)

func init() {
	RootCmd.AddCommand(DeriveCmd)
	DeriveCmd.PersistentFlags().BoolVarP(&hashPath, "mnemonic", "m", false, "Use mnemonic as path")
	DeriveCmd.PersistentFlags().BoolVarP(&customSeedPwd, "custom", "u", false, "Use custom seed derivation password")
	DeriveCmd.PersistentFlags().StringVarP(&keyAddrID, "addr", "a", "0x0", "Custom pkhash address network ID")
	DeriveCmd.PersistentFlags().BoolVar(&bechAddr, "bech", false, "Bech address format")
	DeriveCmd.PersistentFlags().BoolVarP(&btcAddr, "btc", "b", false, "BTC address format")
	DeriveCmd.PersistentFlags().BoolVarP(&printKey, "print-key", "p", false, "Prints private and public key")
}

// DeriveCmd - Key derive command.
var DeriveCmd = &cobra.Command{
	Use:   "derive [seed] [path]",
	Short: "Derives key from seed",
	Long: `Derives key from seed and path.
Path is defined as: m / purpose' / coin_type' / account' / change / address_index

Mnemonic can be used for path by using --force or -f flag.`,
	Example:     "  $ ipfn derive example m/44'/138'/0'/0/0",
	Annotations: map[string]string{"category": "key"},
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("seed argument is required")
		}
		if viper.Get(fmt.Sprintf("seeds.%s", args[0])) == nil {
			return fmt.Errorf("seed %q was not found", args[0])
		}
		if len(args) < 2 {
			return errors.New("path argument is required")
		}
		return nil
	},
	Run: cmdutil.WrapCommand(HandleDeriveCmd),
}

// HandleDeriveCmd - Handles key derive command.
func HandleDeriveCmd(cmd *cobra.Command, args []string) (err error) {
	acc, err := deriveKey(args[0], args[1])
	if err != nil {
		return
	}
	return printAccount(acc)
}

func printAccount(acc *keywallet.ExtendedKey) (err error) {
	pub, err := acc.ECPubKey()
	if err != nil {
		return
	}
	id, err := hexToByte(keyAddrID)
	if err != nil {
		return
	}
	var addr interface{}
	if bechAddr {
		addr, err = pkhash.Base32PKHashString(pub, id)
		if err != nil {
			return
		}
	} else if id != 0 || btcAddr {
		addr, err = acc.PKHash(id)
		if err != nil {
			return
		}
	} else {
		ethaddr, err := acc.Address()
		if err != nil {
			return err
		}
		addr = ethaddr.String()
	}
	if printKey {
		neuter, _ := acc.Neuter()
		logger.Printf("Public key: %s", neuter)
		logger.Printf("Private key: %s", acc)
	}
	logger.Printf("Address: %s", addr)
	c, err := pkhash.PubkeyToCid(pub)
	if err != nil {
		return
	}
	logger.Printf("IPFN address: /ipfn/%s", c)
	return
}

// hexToByte - Converts hex string to byte.
func hexToByte(input string) (_ byte, err error) {
	input = strings.TrimLeft(input, "0x")
	arr, err := hex.DecodeString(input)
	if err != nil {
		return
	}
	if len(arr) != 1 {
		return 0, nil
	}
	return arr[0], nil
}
