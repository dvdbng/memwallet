const ethUtil = require('ethereumjs-util')
const EthereumTx = require('ethereumjs-tx')
const txDecoder = require('ethereum-tx-decoder');

const readline = require('readline');
const async = require('async');


const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function askAddress(next) {
  rl.question(`Address:`, (addr) => {
    if (!ethUtil.isValidAddress(addr)) next(new Error('Invalid address'));
    next(null, addr);
  });
}

async.waterfall([
  (next) => {
    console.log('Insert address to send from');
    askAddress((err, fromAddr) => next(err, { fromAddr }));
  },
  (data, next) => {
    console.log('Insert destination address');
    askAddress((err, toAddr) =>  next(err, { toAddr, ...data }));
  },
  ({ fromAddr, ...data }, next) => {
    console.log(`Insert amount to send in wei (1eth = 1e18wei, check balance in https://etherscan.io/address/${fromAddr}) `);
    rl.question(`Amount (int):`, (amount) => next(null, { value: parseInt(amount, 10), fromAddr, ...data }));
  },
  (data, next) => {
    console.log('Insert desired gas price and limit (check in https://ethgasstation.info/)');
    rl.question(`Gas price (gwei):`, (price) => {
      let gasPrice = parseInt(price, 10) * 1e9;
      rl.question(`Gas limit (int, 21000 for standard tx):`, (limit) => {
        let gasLimit = parseInt(limit, 10);
        next(null, {gasPrice, gasLimit, ...data});
      });
    });
  },
  (data, next) => {
    console.log('Insert transaction input data (hex) leave blank for standard transactions.');
    rl.question(`Input data:`, (inputData) => next(null, { inputData: Buffer.from(inputData, 'hex'), ...data }));
  },
  ({ fromAddr, ...data }, next) => {
    console.log(`Insert address nonce (number of transactions made by the address, check in https://etherscan.io/address/${fromAddr})`);
    rl.question(`nonce (int):`, (nonce) => next(null, { nonce: parseInt(nonce, 10), fromAddr, ...data }));
  },
  (data, next) => {
    console.log('Transaction data', data);
    next(null, data);
  },
  ({ fromAddr, toAddr, inputData, ...data }, next) => {
    const tx = new EthereumTx({
      to: toAddr,
      chainId: 1,
      data: inputData,
      ...data,
    });
    const hash = tx.hash(false);
    console.log(`Hash to sign: ${hash.toString('hex')}`);
    rl.question(`Signature (hex RS buffer):`, (rshex) => {
      const rs = Buffer.from(rshex, 'hex');
      if (rs.length != 64) return next(new Error('Invalid signature format'));
      const r = rs.slice(0, 32);
      const s = rs.slice(32);
      // "crack" recovery id
      v = [27, 28].find((v) => ethUtil.bufferToHex(ethUtil.pubToAddress(ethUtil.ecrecover(hash, v, r, s))) == fromAddr.toLowerCase());
      if (!v) return next(new Error('Invalid signature'));
      tx.r = r;
      tx.s = s;
      tx.v = v + tx._chainId * 2 + 8;
      const error = tx.validate(true);
      if (error) return next(new Error(`Invalid transaction: ${error}`));
      next(null, tx.serialize().toString('hex'));
    });
  },
], (err, result) => {
  if (err) console.log("ERROR: " + err);
  else {
    console.log('Ethereum tx:');
    console.log(result);
    console.log('Decoded:')
    console.log(txDecoder.decodeTx('0x' + result));
    console.log('Check it looks good and push to blockchain in https://etherscan.io/pushTx');
  }
})
