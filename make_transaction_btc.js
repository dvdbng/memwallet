const BitcoinJS = require('bitcoinjs-lib');
const ecdsa = require('bitcoinjs-lib/src/ecdsa');
const readline = require('readline');
const async = require('async');
const coinSelect = require('coinselect');
const http = require('https');
const request = require('request');


const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function loopAsk(question, itemCallback, doneCallback) {
  rl.question(`${question}:`, (answer) => {
    answer = answer.trim();
    if(answer === 'END') {
      doneCallback();
    } else {
      itemCallback(answer);
      loopAsk(question, itemCallback, doneCallback);
    }
  });
}

function askSpendAddresses(callback){
  let utxos = [];
  loopAsk('Address', answer => {
    //const [vout, value, txId] = answer.split(/\s+/);
    //utxos.push({ vout: parseInt(vout, 10), value: parseInt(value, 10), txId });
    utxos.push(answer);
  }, () => callback(utxos));
}

function askOutputs(callback){
  let utxos = [];
  loopAsk('OUTPUT', answer => {
    const [value, address] = answer.split(/\s+/);
    utxos.push({ value: parseInt(value, 10), address });
  }, () => callback(utxos));
}

function ECPairStub(publicKey, signResult){
  const res = {
    network: BitcoinJS.networks.bitcoin,
    publicKey,

    sign(hash) {
      res.txHash = hash;
      return signResult;
    }
  };
  return res
}

function getHashForSignature(txb, i, script, value, pubKey){
  const stub = ECPairStub(pubKey, null);
  const txbClone = BitcoinJS.TransactionBuilder.fromTransaction(BitcoinJS.Transaction.fromHex(txb.tx.toHex(), txb.tx.network));
  try{
    txbClone.sign(i, stub, script, null, value);
  } catch(e) {
    if(!stub.txHash) throw e;
  }
  return stub.txHash;
}

function askSignature(hash, i, pubKey, callback){
  console.log(`Now signing input ${i}`);
  console.log(`Hash to sign: ${hash.toString('hex')}`)
  rl.question(`Signature (hex):`, (signature) => {
    const ECPair = BitcoinJS.ECPair.fromPublicKeyBuffer(pubKey);
    const RSBuffer = Buffer.from(signature, 'hex');
    if (ecdsa.verify(hash, BitcoinJS.ECSignature.fromRSBuffer(RSBuffer), ECPair.Q)) {
      callback(RSBuffer);
    } else {
      console.log('Invalid signature, try again');
      askSignature(hash, i, pubKey, callback);
    }
  });
}

function askPK(addr, next) {
  rl.question(`Public key for address ${addr} (hex):`, (pk) => {
    let pubKey = Buffer.from(pk, 'hex')

    let version = BitcoinJS.address.fromBase58Check(addr).version;
    if (version === BitcoinJS.networks.bitcoin.scriptHash) {
      let pubKeyHash = BitcoinJS.crypto.hash160(pubKey);
      let redeemScript = BitcoinJS.script.witnessPubKeyHash.output.encode(pubKeyHash);
      let redeemScriptHash = BitcoinJS.crypto.hash160(redeemScript);
      let scriptPubKey = BitcoinJS.script.scriptHash.output.encode(redeemScriptHash);
      let address = BitcoinJS.address.fromOutputScript(scriptPubKey);

      if (addr !== address)  throw new Error('Script hash doesnt match P2SH address');
      next({ redeemScript, pubKey })
    } else if (version === BitcoinJS.networks.bitcoin.pubKeyHash) {
      let keyPair = new BitcoinJS.ECPair.fromPublicKeyBuffer(pubKey);
      let address = keyPair.getAddress();
      if (addr !== address)  throw new Error('Public key doesnt match address');
      next({ pubKey });
    } else {
      throw new Error("Unsupported address")
    }
  });
}

async.waterfall([
  (next) => {
    console.log('Insert addresses to spend:');
    askSpendAddresses((utxos) => next(null, utxos));
  },
  (addrs, next) => {
    let utxos = [];

    async.eachOfSeries(addrs, (addr, i, next) => {
      askPK(addr, ({ pubKey, redeemScript }) => {
        console.log(`Downloading UTXOS for ${addr}...`)
        request.get({url: `https://blockchain.info/unspent?active=${addr}&format=json`, json: true}, (err, res, data) => {
          if (err) {
            console.log(err);
            return next(err);
          }
          data.unspent_outputs.forEach(({ value, tx_hash_big_endian, tx_output_n, script }) => {
            utxos.push({
              outScript: Buffer.from(script, 'hex'),
              pubKey,
              txId: tx_hash_big_endian,
              vout: tx_output_n,
              value,
              script: redeemScript,
            });
          });
          next();
        });
      });
    }, (err) => next(err, utxos));
  },
  (utxos, next) => {
    console.log(utxos);
    console.log('Insert transaction outputs [value] [address]');
    console.log('A charge output will be added automatically. Can be left blank to sweep address');
    console.log('Write END when done.');
    askOutputs((outs) => next(null, utxos, outs));
  },
  (utxos, outs, next) => {
    console.log('Insert desired fee in satoshis per byte (check current in https://bitcoinfees.earn.com/)');
    rl.question(`Fee rate:`, (answer) => {
      let feeRate = parseFloat(answer);
      if (feeRate < 1.024) throw new Error('min relay fee not met');
      next(null, utxos, outs, feeRate);
    });
  },
  (utxos, outs, feeRate, next) => {
    let { inputs, outputs, fee } = coinSelect(utxos, outs, feeRate)
    if (!inputs || !outputs) {
      console.log('Could not select UTXOS to match outputs');
      return next('UTXOS_NO_SOLUTION');
    }
    console.log(`Total fee: ${fee} satoshis, ${fee/1e8}btc`);

    if (outputs.some(({address}) => !address)) {
      rl.question(`Change address:`, (change) => {
        outputs.forEach(o => o.address = o.address || change);
        next(null, inputs, outputs);
      });
    } else {
        next(null, inputs, outputs);
    }
  },
  (inputs, outputs, next) => {
    console.log({ inputs, outputs });
    const txb = new BitcoinJS.TransactionBuilder();
    inputs.forEach(({ vout, txId, outScript }) => txb.addInput(txId, vout, null, outScript));
    outputs.forEach(({ address, value }) => txb.addOutput(address, value));
    console.log('Unsigned transaction:')
    console.log(txb.tx.toHex());
    console.log('Decode and see if it looks good before signing');
    async.eachOfSeries(inputs, ({ script, value, pubKey }, i, next) => {
      let sign_hash = getHashForSignature(txb, i, script, value, pubKey);
      askSignature(sign_hash, i, pubKey, (RSBuffer) => {
        txb.sign(i, ECPairStub(pubKey, RSBuffer), script, null, value);
        next();
      });
    }, () => next(null, txb));
  },
  (txb) => {
    console.log(txb.build().toHex());
  }
])
