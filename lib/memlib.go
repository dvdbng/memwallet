package memlib

import (
  "github.com/ThePiachu/Go/mymath/bitelliptic"
  "github.com/ThePiachu/Go/mymath/bitecdsa"
  b58 "github.com/jbenet/go-base58"
  "golang.org/x/crypto/pbkdf2"
  "golang.org/x/crypto/scrypt"
  "golang.org/x/crypto/ripemd160"
  "golang.org/x/crypto/blake2b"
  "golang.org/x/crypto/sha3"

  //"github.com/ehmry/monero"
  //"github.com/ehmry/monero/crypto"
  //"github.com/vsergeev/btckeygenie/btckey"
  //"github.com/btcsuite/btcutil/base58"

  "encoding/base32"
  "encoding/binary"
  "crypto/sha256"
  "crypto/rand"
  "fmt"
  "time"
  "unicode"
  "os"
  "io"
  "encoding/hex"
  "encoding/base64"
  "math/big"
  "errors"

  "../utils"
)

var S256 = bitelliptic.S256()
var S256_halfOrder = new(big.Int).Sub(S256.N, new(big.Int).SetUint64(2))

func fail(err error) {
  fmt.Printf("%s\n", err)
  os.Exit(1)
}

func ensure_ok (err error) {
  if err != nil {
    fail(err)
  }
}

type xorReader struct {
  salt []byte
  rnd io.Reader
}

func (mr *xorReader) Read(p []byte) (n int, err error) {
  n, err = mr.rnd.Read(p)
  if err != nil { return n, err }

  for i := 0; i < n; i++ {
    p[i] = p[i] ^ mr.salt[i % len(mr.salt)]
  }
  return n, err
}

func XorReader(rnd io.Reader, salt []byte) io.Reader {
  return &xorReader{salt, rnd}
}

func VarInt(size int) ([]byte) {
  if size < 0xFD {
    return []byte{byte(size)}
  } else if size <= 0xFFFF {
    b := make([]byte, 2)
    binary.LittleEndian.PutUint16(b, uint16(size))
    return append([]byte{0xfd}, b...)
  } else {
    fail(errors.New("Messages this long are possible but not implemented"))
  }
  return nil
}

func bytes_to_bigint(b []byte) *big.Int {
  res := big.NewInt(0)
  for i := 0; i < len(b); i++ {
    res.Lsh(res, 8)
    res.Add(res, big.NewInt(int64(b[i])))
  }
  return res
}

func btc_serialize_signature(sigR, sigS *big.Int) [65]byte {
  var seq [65]byte
  seq[0] = 27
  rd := sigR.Bytes()
  sd := sigS.Bytes()
  copy(seq[1+32-len(rd):], rd)
  copy(seq[1+64-len(sd):], sd)
  return seq
}

func to_rs_buffer(sigR, sigS *big.Int) [64]byte {
  var seq [64]byte
  rd := sigR.Bytes()
  sd := sigS.Bytes()
  copy(seq[32-len(rd):], rd)
  copy(seq[64-len(sd):], sd)
  return seq
}

func BTC_sign_msg(message []byte, priv [32]byte) string {
  var messagePrefix = []byte("Bitcoin Signed Message:\n")
  message = append(VarInt(len(message)), message...)
  message = append(messagePrefix, message...)
  message = append(VarInt(len(messagePrefix)), message...)
  hash := ShaTwice(message)
  r, s := S256_sign(hash, priv)
  signature := btc_serialize_signature(r, s)
  return base64.StdEncoding.EncodeToString(signature[:])
}

func BTC_sign_hash(hash [32]byte, priv [32]byte) [64]byte {
  r, s := S256_sign(hash, priv)
  return to_rs_buffer(r, s)
}


func S256_sign(hash [32]byte, priv [32]byte) (r, s *big.Int) {
  curve := S256
  d := bytes_to_bigint(priv[:])
  privk := new(bitecdsa.PrivateKey)
  privk.PublicKey.BitCurve = curve
  privk.D = d
  privk.PublicKey.X, privk.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())

  // Extra seed data
  t0 := time.Now()
  privHash := ShaTwice(priv[:])
  var extraSeedData [64]byte
  copy(extraSeedData[:32], hash[:])
  copy(extraSeedData[32:], privHash[:])
  extraSeedData[7] ^= byte(t0.Nanosecond() % 256)
  extraSeedData[40] ^= byte((t0.Nanosecond()/256) % 256)
  extraSeed := ShaTwice(extraSeedData[:])

  r, s, err := bitecdsa.Sign(XorReader(rand.Reader, extraSeed[:]), privk, hash[:])
  ensure_ok(err)
  low_s_max, _ := new(big.Int).SetString("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0", 16)
  if (s.Cmp(big.NewInt(0)) <= 0 || s.Cmp(low_s_max) == 1) {
    fail(errors.New("Catastrofic error generating signature"))
  }

  return r, s
}

func ShaTwice(a []byte) [32]byte {
  var tmp [32]byte = sha256.Sum256(a)
  return sha256.Sum256(tmp[:])
}

func Ripemd160(a []byte) []byte {
  shaHasher := sha256.New()
  shaHasher.Write(a)
  ripemdHasher := ripemd160.New()
  ripemdHasher.Write(shaHasher.Sum(nil))
  return ripemdHasher.Sum(nil)
}

func Keccak256(data []byte) []byte {
  hash := sha3.NewLegacyKeccak256()
  hash.Write(data)
  return hash.Sum(nil)
}

func Reversed(str []byte) (result []byte) {
  for i := len(str) - 1; i >= 0; i-- {
    result = append(result, str[i])
  }
  return result
}

func Raiblocks_priv_to_pub (seed [32] byte) ed25519.PublicKey {
  publicKey, _ := ed25519.GenerateKey(seed)
  return publicKey
}

func Raiblocks_seed_to_priv (seed [32] byte) ed25519.PrivateKey {
  _, privateKey := ed25519.GenerateKey(seed)
  return privateKey
}

func Raiblocks_GetAddressChecksum(pub ed25519.PublicKey) []byte {
  hash, err := blake2b.New(5, nil)
  if err != nil { panic("Unable to create hash") }
  hash.Write(pub)
  return Reversed(hash.Sum(nil))
}

func Raiblocks_public_to_address (pub ed25519.PublicKey) string {
  // xrb uses a non-standard base32 character set.
  XrbEncoding := base32.NewEncoding("13456789abcdefghijkmnopqrstuwxyz")
  // Pubkey is 256bits, base32 must be multiple of 5 bits
  // to encode properly.
  // Pad the start with 0's and strip them off after base32 encoding
  padded := append([]byte{0, 0, 0}, pub...)
  address := XrbEncoding.EncodeToString(padded)[4:]
  checksum := XrbEncoding.EncodeToString(Raiblocks_GetAddressChecksum(pub))
  return "xrb_" + address + checksum
}


func S256_priv_to_pub (priv [32]byte) [65]byte {
  var ret [65]byte
  x, y := S256.ScalarBaseMult(priv[:])
  xbytes := x.Bytes()
  ybytes := y.Bytes()
  ret[0] = 4
  copy(ret[1 + 32 - len(xbytes):33], xbytes)
  copy(ret[33 + 32 - len(ybytes):65], ybytes)
  return ret
}

func S256_priv_to_pub_compressed(priv [32]byte) [33]byte {
  var ret [33]byte
  x, y := S256.ScalarBaseMult(priv[:])
  xbytes := x.Bytes()
  if y.Bit(0) == 0 {
    ret[0] = 0x02
  } else {
    ret[0] = 0x03
  }
  copy(ret[1 + 32 - len(xbytes):33], xbytes)
  return ret
}

func base58_check_encode(in []byte) string {
  return b58.EncodeAlphabet(in, b58.BTCAlphabet)
}

func WIF_encode(data []byte, version byte) string {
  var bytes []byte = append([]byte{version}, data...)
  sh := ShaTwice(bytes[:])
  return string(base58_check_encode(append(bytes, sh[:4]...)))
}

func BTCish_public_to_address(public []byte, version byte) string {
  return WIF_encode(Ripemd160(public[:]), version)
}

func BTCish_private_to_WIF(priv [32]byte, version byte) string {
  return WIF_encode(priv[:], version)
}

func BTCish_private_to_WIF_compressed(priv [32]byte, version byte) string {
  return WIF_encode(append(priv[:], 0x01), version)
}

func BTCish_public_to_segwit_redeem_script(pub_uncompressed [33]byte) []byte {
  pk_hash := Ripemd160(pub_uncompressed[:])
  var result []byte = append([]byte{0x00, 0x14}, pk_hash...)
  return result;
}

func BTC_redeem_script_to_address(redeem_script []byte, version byte) string {
  return WIF_encode(Ripemd160(redeem_script), version)
}

func Warpwallet_secret(passphrase string, salt string, hash_pad byte) [32]byte {
  var result [32]byte
  _passphrase := fmt.Sprint(passphrase, string(rune(hash_pad)))
  _salt := fmt.Sprint(salt, string(rune(hash_pad)))
  key, _ := scrypt.Key([]byte(_passphrase), []byte(_salt), 262144, 8, 1, 32)

  _passphrase = fmt.Sprint(passphrase, string(rune(hash_pad + 1)))
  _salt = fmt.Sprint(salt, string(rune(hash_pad + 1)))
  key2 := pbkdf2.Key([]byte(_passphrase), []byte(_salt), 65536, 32, sha256.New)

  for i := 0; i < len(key); i++ {
      result[i] = key[i] ^ key2[i]
  }
  return result
}

func Ethereum_public_to_address(pub_key [65]byte) string {
  hash := Keccak256(pub_key[1:])
  addr := hex.EncodeToString(hash[12:])
  addr_runes := []rune(addr)
  addr_hash := hex.EncodeToString(Keccak256([]byte(addr)))
  for i := 0; i < 40; i++ {
    if addr_hash[i] >= '8' {
      addr_runes[i] = unicode.ToUpper(addr_runes[i])
    }
  }
  return "0x" + string(addr_runes);
}

func Default_hash_pad_for_currency(currency string) int {
  if currency == "bitcoin" {
    return 1
  } else if  currency == "litecoin" {
    return 2
  } else if  currency == "monero" {
    return 3
  } else if  currency == "ethereum" {
    return 4
  } else if  currency == "testnet" {
    return 5
  } else if  currency == "garlicoin" {
    return 6
  } else if  currency == "raiblocks" {
    return 7
  }
  return -1
}

func slice2arr(in []byte) [32]byte {
  var out [32]byte;
  copy(out[0:32], in)
  return out
}

func Bitcoin_ish(name string, pkh byte, sh byte, wif byte, seed [32]byte, print_addr bool, print_priv bool, sign_msg string, sign_hash_buf []byte) {
  pub_key_uncompressed := S256_priv_to_pub(seed)
  pub_key_compressed := S256_priv_to_pub_compressed(seed)
  addr_compressed := BTCish_public_to_address(pub_key_compressed[:], pkh)
  addr_uncompressed := BTCish_public_to_address(pub_key_uncompressed[:], pkh)
  if(print_addr) {
    fmt.Printf("%s Address (Uncompressed): %s\n", name, addr_uncompressed)
    fmt.Printf("%s Address (Compressed): %s\n", name, addr_compressed)
    if (sh != 0) {
      segwit_redeem_script := BTCish_public_to_segwit_redeem_script(pub_key_compressed)
      fmt.Printf("Segwit P2SH Address: %s\n", BTC_redeem_script_to_address(segwit_redeem_script, 5))
      fmt.Printf("Segwit Redeem Script (Uncompressed): %x\n", segwit_redeem_script)
    }
    fmt.Printf("Pub Key (Uncompressed): %x\n", pub_key_uncompressed)
    fmt.Printf("Pub Key (Compressed): %x\n", pub_key_compressed)
  }
  if(print_priv) { fmt.Printf("Private Key (Uncompressed): %s\n", BTCish_private_to_WIF(seed, wif)) }
  if(print_priv) { fmt.Printf("Private Key (Compressed): %s\n", BTCish_private_to_WIF_compressed(seed, wif)) }
  if(sign_msg != "") {
    signature := BTC_sign_msg([]byte(sign_msg), seed)
    fmt.Printf("Signature: %s\n", signature)
    fmt.Printf("-----BEGIN BITCOIN SIGNED MESSAGE-----\n%s\n-----BEGIN SIGNATURE-----\n%s\n%s\n-----END BITCOIN SIGNED MESSAGE-----\n", sign_msg, addr_uncompressed, signature)
  }
  if(sign_hash_buf != nil) {
    signature := BTC_sign_hash(slice2arr(sign_hash_buf), seed)
    fmt.Printf("Signature: %x\n", signature)
  }
}

func Raiblocks(seed [32]byte, print_addr bool, print_priv bool, sign_msg string, sign_hash_buf []byte) {
  pub_key := Raiblocks_priv_to_pub(seed)
  addr := Raiblocks_public_to_address(pub_key)
  if(print_addr) {
    fmt.Printf("Raiblocks Address (Uncompressed): %s\n", addr)
    fmt.Printf("Pub Key (Uncompressed): %x\n", pub_key)
  }
  if(print_priv) { fmt.Printf("Private Key: %x\n", seed) }
  if(sign_hash_buf != nil) {
    signature := ed25519.Sign(Raiblocks_seed_to_priv(seed), sign_hash_buf)
    fmt.Printf("Signature: %x\n", signature)
  }
}

func Ethereum(seed [32]byte, print_addr bool, print_priv bool, sign_msg string, sign_hash_buf []byte) {
  pub_key := S256_priv_to_pub(seed)
  addr := Ethereum_public_to_address(pub_key)
  if(print_addr) {
    fmt.Printf("Ethereum Address (Uncompressed): %s\n", addr)
    fmt.Printf("Pub Key (Uncompressed): %x\n", pub_key)
  }
  if(print_priv) { fmt.Printf("Private Key: %x\n", seed) }
  if(sign_hash_buf != nil) {
    signature := BTC_sign_hash(slice2arr(sign_hash_buf), seed)
    fmt.Printf("Signature: %x\n", signature)
  }
}

