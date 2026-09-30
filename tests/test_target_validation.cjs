const assert = require('node:assert/strict');
const {test} = require('node:test');
const {isPublicIpAddress} = require('../public/target-validation.js');
test('conservative public IP parser rejects malformed and special-purpose addresses', () => {
  for (const address of ['8.8.8.8','1.1.1.1','2001:4860:4860::8888','2606:4700:4700::1111']) {
    assert.equal(isPublicIpAddress(address), true, address);
  }
  for (const address of ['999.1.1.1','010.1.2.3','100.64.0.1','127.0.0.1','169.254.169.254',
    '192.168.1.1','192.0.2.1','198.18.0.1','203.0.113.1','224.0.0.1','::::','1:2:3','::',
    '::1','fc00::1','fe80::1','ff02::1','2001:db8::1','2001:0::1','2001:2::1','2002::1',
    '3fff:fff::1','::ffff:127.0.0.1','1:2:3:4:5:6:7:8:9']) {
    assert.equal(isPublicIpAddress(address), false, address);
  }
});
