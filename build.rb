require 'digest'
system('rm -f -r ./warpwallet ./pkg')

expected_pkgs = {
  'ce76f423d92e7b64b81dc15dc78c9b2b' => 'src/github.com/ThePiachu/Go/mymath/bitelliptic/bitelliptic.go',
  'a20222f19fae8a66ff60ef0c2ec36b0c' => 'src/github.com/ThePiachu/Go/mymath/bitecdsa/bitecdsa.go',
  '26fd760cc7aee1b25668fbf6d4f42b35' => 'src/github.com/jbenet/go-base58/base58.go',

  'abf1d791399ffd9ff4483e847998a799' => 'src/golang.org/x/crypto/scrypt/scrypt.go',
  '0aa027a87deaad179e079d88b0df91be' => 'src/golang.org/x/crypto/ripemd160/ripemd160.go',
  '4587c98398c66cc06ddbc34b3bb3bf57' => 'src/golang.org/x/crypto/ripemd160/ripemd160block.go',
  'f9d28bcecfb4a553f6bc7abe724ceadd' => 'src/golang.org/x/crypto/pbkdf2/pbkdf2.go',

  '3bc3733c2162874f6451adbca1c4dd52' => 'src/golang.org/x/crypto/blake2b/blake2b.go',
  'df7eab6ad6cd40e5e48f6266e38504d2' => 'src/golang.org/x/crypto/blake2b/blake2b_generic.go',
  '4eaddf8cdcc42e3e3c1a2c5fe72adf14' => 'src/golang.org/x/crypto/blake2b/blake2b_amd64.go',

  'bc4095bb30b736729da43ac9b6074567' => 'src/golang.org/x/crypto/sha3/hashes.go',
  '58cc59aa11377c1fe5340650551c9087' => 'src/golang.org/x/crypto/sha3/hashes_generic.go',
  '58fac3b5ca71d8eab3c334a65e992497' => 'src/golang.org/x/crypto/sha3/keccakf_amd64.go',
  '246bdf5354a51a03d0df2059ab4b9bc2' => 'src/golang.org/x/crypto/sha3/keccakf_amd64.s',
  'f26149e9bce504a2a05a183224ea0d54' => 'src/golang.org/x/crypto/sha3/sha3.go',
  '86af78583c20719dac4ad9444722dd4b' => 'src/golang.org/x/crypto/sha3/xor_unaligned.go'
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

