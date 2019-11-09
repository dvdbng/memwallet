package main

import (
  "encoding/hex"
  "fmt"
  "flag"
  "os"

  "./lib"
)

var fs = flag.NewFlagSet("options", flag.PanicOnError)

func usage () {
  fmt.Printf("Usage: %s [options...]\n", os.Args[0])
  fs.PrintDefaults()
  fmt.Printf("Required: passphrase, salt\n")
  os.Exit(1)
}

func fail(err error) {
  fmt.Printf("%s\n", err)
  os.Exit(1)
}

func main () {
    hash_pad := fs.Int("hash_pad", 0, "Pad to use in warpwallet algoritm")
    print_priv := fs.Bool("print-priv", false, "Print private key")
    print_addr := fs.Bool("print-addr", false, "Print address")
    sign_msg := fs.String("sign", "", "Sign a message")
    sign_hash := fs.String("sign-hash", "", "Sign a transaction hash")
    currency_addr := fs.String("currency", "bitcoin", "Currency to use. Currently supported are bitcoin, monero, litecoin, ethereum, testnet, raiblocks")
    passphrase_addr := fs.String("passphrase", "", "Warpwallet passphrase")
    salt_addr := fs.String("salt", "", "Warpwallet salt")

    fs.Parse(os.Args[1:])

    currency := *currency_addr
    passphrase := *passphrase_addr
    salt := *salt_addr

    //fmt.Printf("%s %s %s\n", currency, passphrase, salt)

    if memlib.Default_hash_pad_for_currency(currency) < 0 || passphrase == "" || salt == "" || len(fs.Args()) > 0 {
      usage()
    }


    if(*hash_pad == 0) {
      *hash_pad = memlib.Default_hash_pad_for_currency(currency)
    }

    //fmt.Printf("Passphrase: %s\nSalt: %s\nHashPad: %d\n", passphrase, salt, hash_pad)
    result := memlib.Warpwallet_secret(passphrase, salt, byte(*hash_pad))
    //fmt.Printf("Seed: %x\n", result)
    var sign_hash_buf []byte = nil
    var err error
    if (*sign_hash) != "" {
      sign_hash_buf, err = hex.DecodeString(*sign_hash)
      if err != nil { fail(err) }
    }

    if currency == "bitcoin" {
                                          memlib.Bitcoin_ish("Bitcoin",   0x00, 0x05, 0x80, result, *print_addr, *print_priv, *sign_msg, sign_hash_buf)
    } else if currency == "testnet" {
                                          memlib.Bitcoin_ish("Testnet",   0x6f, 0xc4, 0xef, result, *print_addr, *print_priv, *sign_msg, sign_hash_buf)
    } else if currency == "litecoin" {
                                          memlib.Bitcoin_ish("Litecoin",  0x30,    0, 0xb0, result, *print_addr, *print_priv, *sign_msg, sign_hash_buf)
    } else if currency == "garlicoin" {
                                          memlib.Bitcoin_ish("Garlicoin", 0x26,    0, 0xb0, result, *print_addr, *print_priv, *sign_msg, sign_hash_buf)
    } else if currency == "raiblocks" {
                                          memlib.Raiblocks(result, *print_addr, *print_priv, *sign_msg, sign_hash_buf)
    } else if currency == "ethereum" {
                                          memlib.Ethereum(result, *print_addr, *print_priv, *sign_msg, sign_hash_buf)
    } else if currency == "monero" {
      //var secret [32]byte;
      //var view_secret [32]byte;
      //var spend_secret [32]byte;
      //crypto.SecretFromSeed(&secret, &result)
      //account, err := monero.RecoverAccount(secret)
      //if err != nil {
      //  fail(err)
      //}
      //spend_secret = account.Secret()
      //crypto.ViewFromSpend(&view_secret, &spend_secret)
      //fmt.Printf("Address: %s\n", account.Address().String())
      //fmt.Printf("Private Spend Key: %x\n", spend_secret)
      //fmt.Printf("Private View Key: %x\n", view_secret)
      //mnemonic, err := account.Mnemonic()
      //if err != nil {
      //  fail(err)
      //}
      //fmt.Printf("Mnemonic: %s\n", mnemonic)
    }
}
