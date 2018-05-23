require 'digest'
system('rm -f -r ./warpwallet ./pkg')

expected_pkgs = {
  #'9ba54cc4b69478b691526ec5b972b069' => 'src/github.com/vsergeev/btckeygenie/btckey/elliptic.go',
  #'9e3f960f49c8f31044fad08335aa2dba' => 'src/github.com/vsergeev/btckeygenie/btckey/btckey.go',

  '06005f21dadaa2938c2069e7521f52f5' => 'src/golang.org/x/crypto/scrypt/scrypt.go',
  '416c534c652727476f6d545a599601ce' => 'src/golang.org/x/crypto/ripemd160/ripemd160.go',
  '0d36148ce6c0821409a0be2d7bfde4b0' => 'src/golang.org/x/crypto/ripemd160/ripemd160block.go',
  'f9d28bcecfb4a553f6bc7abe724ceadd' => 'src/golang.org/x/crypto/pbkdf2/pbkdf2.go',

  'ce76f423d92e7b64b81dc15dc78c9b2b' => 'src/github.com/ThePiachu/Go/mymath/bitelliptic/bitelliptic.go',
  'a20222f19fae8a66ff60ef0c2ec36b0c' => 'src/github.com/ThePiachu/Go/mymath/bitecdsa/bitecdsa.go',
  '26fd760cc7aee1b25668fbf6d4f42b35' => 'src/github.com/jbenet/go-base58/base58.go',

  '3e9787f8fcaa0f1e4b5387f9eb5533af' => 'src/golang.org/x/crypto/blake2b/blake2b.go',
  '01817309b90c01500ee15127a498cd4c' => 'src/golang.org/x/crypto/blake2b/blake2b_ref.go',
  '748a7ff139259328aac9776add98d449' => 'src/golang.org/x/crypto/blake2b/blake2b_generic.go',

  '77e38ecf7567eec42ca73a6f919b6b3d' => 'src/github.com/ethereum/go-ethereum/crypto/sha3/hashes.go',
  'ce6b72f18ca816dd52721347eaba0402' => 'src/github.com/ethereum/go-ethereum/crypto/sha3/keccakf_amd64.go',
  '246bdf5354a51a03d0df2059ab4b9bc2' => 'src/github.com/ethereum/go-ethereum/crypto/sha3/keccakf_amd64.s',
  '5bce29d1ffcf1517c799af1c85dc238d' => 'src/github.com/ethereum/go-ethereum/crypto/sha3/sha3.go',
  'e6e13b0bc0f693d9d10e8fae1f9687b4' => 'src/github.com/ethereum/go-ethereum/crypto/sha3/xor_unaligned.go',

}.invert

actual_pkgs = `find src -type f`.split("\n")

def fail(msg)
  puts msg
  exit 1
end

(actual_pkgs - expected_pkgs.keys).each do |pkg|
  puts "Unexpected #{pkg}"
end

actual_pkgs.each do |pkg|
  fail "Unexpected pkg #{pkg}" unless expected_pkgs.key? pkg
  file_cnt = File.read(pkg)
  if !pkg[/keccakf_amd64.s$/] && file_cnt[/.{180}/]
    # Ban long lines to avoid malicious code that hides to the right of the screen during review
    fail "Line too long!! in file #{pkg}"
  end
  fail "Invalid signature for #{pkg}" unless Digest::MD5.hexdigest(file_cnt) == expected_pkgs.fetch(pkg)
end

(expected_pkgs.keys - actual_pkgs).each do |pkg|
  fail "missing pkg #{pkg}"
end

exec("env GOPATH=#{Dir.pwd} go build && md5sum memwallet")

