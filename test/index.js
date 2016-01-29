'use strict';

var assert = require('assert');
var nodeWeixinCrypto = require('../lib');

var app = {
  id: 'id',
  encodingAESKey: 'kpAuxitA7JqPW69cQoIS4N4rX2jUhRrVUpH69vAYlWI',
  token: 'token'
};

describe('node-weixin-crypto', function () {
  it('should be able to encrypt/decrypt!', function () {
    var plainText = 'hello';
    var encrypted = nodeWeixinCrypto.encrypt(plainText, app);
    var decrypted = nodeWeixinCrypto.decrypt(encrypted, app);
    assert.equal(true, decrypted === plainText);
  });
  it('should be able to sign!', function () {
    var plainText = 'hello world!';
    var signed = nodeWeixinCrypto.sign(plainText, app, 1454065804077, 'nonce');
    assert.equal(true, signed.length === 40);
  });
});
