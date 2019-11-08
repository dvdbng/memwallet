package main

import (
  "encoding/hex"
  "fmt"
  "flag"
  "os"

  "./lib"
  "./utils"
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

func slice2arr(in []byte) [32]byte {
  var out [32]byte;
  copy(out[0:32], in)
  return out
}

func bitcoin_ish(name string, pkh byte, sh byte, wif byte, seed [32]byte, print_addr bool, print_priv bool, sign_msg string, sign_hash_buf []byte) {
  pub_key_uncompressed := memlib.S256_priv_to_pub(seed)
  pub_key_compressed := memlib.S256_priv_to_pub_compressed(seed)
  addr_compressed := memlib.BTCish_public_to_address(pub_key_compressed[:], pkh)
  addr_uncompressed := memlib.BTCish_public_to_address(pub_key_uncompressed[:], pkh)
  if(print_addr) {
    fmt.Printf("%s Address (Uncompressed): %s\n", name, addr_uncompressed)
    fmt.Printf("%s Address (Compressed): %s\n", name, addr_compressed)
    if (sh != 0) {
      segwit_redeem_script := memlib.BTCish_public_to_segwit_redeem_script(pub_key_compressed)
      fmt.Printf("Segwit P2SH Address: %s\n", memlib.BTC_redeem_script_to_address(segwit_redeem_script, 5))
      fmt.Printf("Segwit Redeem Script (Uncompressed): %x\n", segwit_redeem_script)
    }
    fmt.Printf("Pub Key (Uncompressed): %x\n", pub_key_uncompressed)
    fmt.Printf("Pub Key (Compressed): %x\n", pub_key_compressed)
  }
  if(print_priv) { fmt.Printf("Private Key (Uncompressed): %s\n", memlib.BTCish_private_to_WIF(seed, wif)) }
  if(print_priv) { fmt.Printf("Private Key (Compressed): %s\n", memlib.BTCish_private_to_WIF_compressed(seed, wif)) }
  if(sign_msg != "") {
    signature := memlib.BTC_sign_msg([]byte(sign_msg), seed)
    fmt.Printf("Signature: %s\n", signature)
    fmt.Printf("-----BEGIN BITCOIN SIGNED MESSAGE-----\n%s\n-----BEGIN SIGNATURE-----\n%s\n%s\n-----END BITCOIN SIGNED MESSAGE-----\n", sign_msg, addr_uncompressed, signature)
  }
  if(sign_hash_buf != nil) {
    signature := memlib.BTC_sign_hash(slice2arr(sign_hash_buf), seed)
    fmt.Printf("Signature: %x\n", signature)
  }
}

func raiblocks(seed [32]byte, print_addr bool, print_priv bool, sign_msg string, sign_hash_buf []byte) {
  pub_key := memlib.Raiblocks_priv_to_pub(seed)
  addr := memlib.Raiblocks_public_to_address(pub_key)
  if(print_addr) {
    fmt.Printf("Raiblocks Address (Uncompressed): %s\n", addr)
    fmt.Printf("Pub Key (Uncompressed): %x\n", pub_key)
  }
  if(print_priv) { fmt.Printf("Private Key: %x\n", seed) }
  if(sign_hash_buf != nil) {
    signature := ed25519.Sign(memlib.Raiblocks_seed_to_priv(seed), sign_hash_buf)
    fmt.Printf("Signature: %x\n", signature)
  }
}

func ethereum(seed [32]byte, print_addr bool, print_priv bool, sign_msg string, sign_hash_buf []byte) {
  pub_key := memlib.S256_priv_to_pub(seed)
  addr := memlib.Ethereum_public_to_address(pub_key)
  if(print_addr) {
    fmt.Printf("Ethereum Address (Uncompressed): %s\n", addr)
    fmt.Printf("Pub Key (Uncompressed): %x\n", pub_key)
  }
  if(print_priv) { fmt.Printf("Private Key: %x\n", seed) }
  if(sign_hash_buf != nil) {
    signature := memlib.BTC_sign_hash(slice2arr(sign_hash_buf), seed)
    fmt.Printf("Signature: %x\n", signature)
  }
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
                                          bitcoin_ish("Bitcoin",   0x00, 0x05, 0x80, result, *print_addr, *print_priv, *sign_msg, sign_hash_buf)
    } else if currency == "testnet" {
                                          bitcoin_ish("Testnet",   0x6f, 0xc4, 0xef, result, *print_addr, *print_priv, *sign_msg, sign_hash_buf)
    } else if currency == "litecoin" {
                                          bitcoin_ish("Litecoin",  0x30,    0, 0xb0, result, *print_addr, *print_priv, *sign_msg, sign_hash_buf)
    } else if currency == "garlicoin" {
                                          bitcoin_ish("Garlicoin", 0x26,    0, 0xb0, result, *print_addr, *print_priv, *sign_msg, sign_hash_buf)
    } else if currency == "raiblocks" {
                                          raiblocks(result, *print_addr, *print_priv, *sign_msg, sign_hash_buf)
    } else if currency == "ethereum" {
                                          ethereum(result, *print_addr, *print_priv, *sign_msg, sign_hash_buf)
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
