package memlib

import (
  "testing"
  "encoding/hex"
)


func assertEqual(expected, got interface{}, t *testing.T) {
  if got != expected {
    t.Errorf("Expected '%v', got '%v'", expected, got)
  }
}

func b58test(input string, expected string, t *testing.T) {
  input_bytes, _ := hex.DecodeString(input)
  got := base58_check_encode(input_bytes)
  assertEqual(expected, got, t)
}

func TestEncode(t *testing.T) {
  b58test("", "", t)
  b58test("61", "2g", t)
  b58test("626262", "a3gV", t)
  b58test("636363", "aPEr", t)
  b58test("73696d706c792061206c6f6e6720737472696e67", "2cFupjhnEsSn59qHXstmK2ffpLv2", t)
  b58test("00eb15231dfceb60925886b67d065299925915aeb172c06647", "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L", t)
  b58test("516b6fcd0f", "ABnLTmg", t)
  b58test("bf4f89001e670274dd", "3SEo3LWLoPntC", t)
  b58test("572e4794", "3EFU7m", t)
  b58test("ecac89cad93923c02321", "EJDM8drfXA6uyA", t)
  b58test("10c8511e", "Rt5zm", t)
  b58test("00000000000000000000", "1111111111", t)
}

func WIFtest(input string, expected string, t *testing.T) {
  input_bytes, err := hex.DecodeString(input)
  if(err != nil) { t.Error(err) }
  var priv [32]byte
  copy(priv[:], input_bytes[:])
  assertEqual(expected, WIF_encode(priv[:], 0x80), t)
}

func TestWIF(t *testing.T) {
  WIFtest("27B0C3E53DF30B54B64EFB2DA3194FDAB2E9B748F48AAB2AB24B19AEBE0FDE67", "5J7mRR8j5CFAVAd8VTLYPrmrgHBoAu2iGQyNyFdrBpbqMCWKujb", t)
  WIFtest("CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5", "5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR", t)
  WIFtest("09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE", "5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5", t)
  WIFtest("A43A940577F4E97F5C4D39EB14FF083A98187C64EA7C99EF7CE460833959A519", "5K4caxezwjGCGfnoPTZ8tMcJBLB7Jvyjv4xxeacadhq8nLisLR2", t)
  WIFtest("C2C8036DF268F498099350718C4A3EF3984D2BE84618C2650F5171DCC5EB660A", "5KJ51SgxWaAYR13zd9ReMhJpwrcX47xTJh2D3fGPG9CM8vkv5sH", t)
  WIFtest("44EA95AFBF138356A05EA32110DFD627232D0F2991AD221187BE356F19FA8190", "5JLdxTtcTHcfYcmJsNVy1v2PMDx432JPoYcBTVVRHpPaxUrdtf8", t)
  WIFtest("CA2759AA4ADB0F96C414F36ABEB8DB59342985BE9FA50FAAC228C8E7D90E3006", "5KMKKuUmAkiNbA3DazMQiLfDq47qs8MAEThm4yL8R2PhV1ov33D", t)
}

func S256Test(priv, expected string, t *testing.T) {
  priv_slice, _ := hex.DecodeString(priv)
  var priv_bytes [32]byte
  copy(priv_bytes[:], priv_slice)
  pub := S256_priv_to_pub(priv_bytes)

  assertEqual(expected, hex.EncodeToString(pub[:]), t)
}

func TestS256Derive(t *testing.T) {
  S256Test("AA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522", "0434f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c60b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232", t)
  S256Test("7E2B897B8CEBC6361663AD410835639826D590F393D90A9538881735256DFAE3", "04d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575131c670d414c4546b88ac3ff664611b1c38ceb1c21d76369d7a7a0969d61d97d", t)
  S256Test("6461E6DF0FE7DFD05329F41BF771B86578143D4DD1F7866FB4CA7E97C5FA945D", "04e8aecc370aedd953483719a116711963ce201ac3eb21d3f3257bb48668c6a72fc25caf2f0eba1ddb2f0f3f47866299ef907867b7d27e95b3873bf98397b24ee1", t)
  S256Test("376A3A2CDCD12581EFFF13EE4AD44C4044B8A0524C42422A7E1E181E4DEECCEC", "0414890e61fcd4b0bd92e5b36c81372ca6fed471ef3aa60a3e415ee4fe987daba1297b858d9f752ab42d3bca67ee0eb6dcd1c2b7b0dbe23397e66adc272263f982", t)
  S256Test("1B22644A7BE026548810C378D0B2994EEFA6D2B9881803CB02CEFF865287D1B9", "04f73c65ead01c5126f28f442d087689bfa08e12763e0cec1d35b01751fd735ed3f449a8376906482a84ed01479bd18882b919c140d638307f0c0934ba12590bde", t)
}

func RaiblocksTest(t *testing.T, seed, expected string) {
  priv_slice, _ := hex.DecodeString(seed)
  var priv_bytes [32]byte
  copy(priv_bytes[:], priv_slice)
  pub := Raiblocks_public_to_address(Raiblocks_priv_to_pub(priv_bytes))
  assertEqual(expected, pub, t)
}

func TestRaiblocksDerive(t *testing.T) {
  RaiblocksTest(t, "19A63268B69CF923B9721DB07D21971626DC37A7B0E36853959DB282C6FF4D7B", "xrb_393ndpzcp1j3ybujn1djxhe4dh7sdwbp9e3ertt7ue4t8j9oadxdxfci6sfz")
  RaiblocksTest(t, "97FA00AECBEAA911CB87EA459E30F700ABB3924394F6DE37AF0E9BB3C70A713D", "xrb_1rj6889sckekwhdapmuf4hcbsw38eiu7oc6g3y4fehxsapu9dch3kiwgcbds")
}


func BTCPublicToAddressTest(pub_hex string, expected string, t *testing.T) {
  pub_slice, err := hex.DecodeString(pub_hex)
  if(err != nil) { t.Error(err) }
  assertEqual(expected, BTCish_public_to_address(pub_slice, 0x00), t)
}

func TestBTCPublicToAddress(t *testing.T) {
  BTCPublicToAddressTest("0434f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c60b71ea9bd730fd8923f6d25a7a91e7dd7728a960686cb5a901bb419e0f2ca232", "1FrGABd9gtxGTMEqKZoUhFPT45QUXEMpLN", t)
  BTCPublicToAddressTest("04B9CC0C0DF0384403B8931EC659B36CD0EBAF8CE1F070FD37D2F9E76F2D3478329CB7C03B2E0C41BAF1DB997FCE15684F7B4659F6B9B3C8DCFD1E6FC60D013C19", "1Fvc3riT7j5nQ3oUuDNBYxZK6MAcFcwvqD", t)
}


func Keccak256Test(in string, expected string, t *testing.T) {
  out := Keccak256([]byte(in))
  assertEqual(expected, hex.EncodeToString(out), t)
}

func TestKeccak256(t *testing.T) {
  Keccak256Test("", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", t)
  Keccak256Test("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "45d3b367a6904e6e8d502ee04999a7c27647f91fa845d456525fd352ae3d7371", t)
}

func Ethereum_public_to_addressTest(pub_hex string, expected string, t *testing.T) {
  var pub_bytes [65]byte;
  pub_slice, err := hex.DecodeString(pub_hex)
  if(err != nil) { t.Error(err) }
  copy(pub_bytes[:], pub_slice)
  addr := Ethereum_public_to_address(pub_bytes)
  assertEqual(expected, addr, t)
}

func TestEthereum_public_to_address(t *testing.T) {
  Ethereum_public_to_addressTest("046cb84859e85b1d9a27e060fdede38bb818c93850fb6e42d9c7e4bd879f8b9153fd94ed48e1f63312dce58f4d778ff45a2e5abb08a39c1bc0241139f5e54de7df", "0xAFdEfC1937AE294C3Bd55386A8b9775539d81653", t)
  Ethereum_public_to_addressTest("04a40ca958ebaf491dea2a7596a4f3f7feb5fcf7f1f2f16e4c663ad4b7eb5ca5cdeb324cc88b55d98973038f4e309eac4f6fe32f7827807c046f733ef447ddf81e", "0x028C93e74447aA90241f1f4619c03e19CEc78Bbe", t)
}
