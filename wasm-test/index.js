require('./request-polyfill');
const vade = require('../dist/vade_evan');

const TEST_DID = 'did:evan:zkp:0x6c8ee6e4ca7a7038ce540da6319b6d91bf9970891ecc871b1ede0bd1877e7c17';

(async () => {
  console.log(await vade.did_resolve(TEST_DID));
})();