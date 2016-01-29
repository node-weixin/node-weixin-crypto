'use strict';
var crypto = require('crypto');

var pcks7 = {
  unpad: function(text) {
    var pad = text[text.length - 1];
    if (pad < 1 || pad > 32) {
      pad = 0;
    }
    return text.slice(0, text.length - pad);
  },
  pad: function(text) {
    var k = 32;
    var n = text.length;
    var pads = k - n % k;
    var buffer = new Buffer(pads);
    buffer.fill(pads);
    var tb = new Buffer(text);
    return Buffer.concat([tb, buffer]);
  }
};

module.exports = {
  encrypt: function(plainText, app) {
    // Random Bytes Generation
    var randomBytes = crypto.pseudoRandomBytes(16);

    var textBuffer = new Buffer(plainText);

    // 4 Bytes Network Sequential Long buffr
    var fourBitSequence = new Buffer(4);
    fourBitSequence.writeUInt32BE(textBuffer.length, 0);

    var encBuffer = Buffer.concat([new Buffer(randomBytes), fourBitSequence, textBuffer, new Buffer(app.id)]);

    var padded = pcks7.pad(encBuffer);

    var key = new Buffer(app.encodingAESKey + '=', 'base64');
    if (key.length !== 32) {
      throw Error('encodingAESKey Length Error');
    }
    var iv = key.slice(0, 16);

    var cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    cipher.setAutoPadding(false);

    var encrypted = Buffer.concat([cipher.update(padded), cipher.final()]);
    return encrypted.toString('base64');
  },

  decrypt: function(encrypted, app) {
    var key = new Buffer(app.encodingAESKey + '=', 'base64');
    if (key.length !== 32) {
      throw Error('encodingAESKey Length Error');
    }
    var iv = key.slice(0, 16);

    var decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    decipher.setAutoPadding(false);
    var decrypted = Buffer.concat([decipher.update(encrypted, 'base64'), decipher.final()]);

    var unpadded = pcks7.unpad(decrypted);

    var wrapped = unpadded.slice(16);
    var length = wrapped.slice(0, 4).readUInt32BE(0);
    return wrapped.slice(4, length + 4).toString();
  },

  sign: function(text, app, timestamp, nonce) {
    var encrypted = this.encrypt(text, app);
    var sha1 = crypto.createHash('sha1');
    var sortable = [app.token, timestamp, nonce, encrypted].sort();
    sha1.update(sortable.join(''));
    return sha1.digest('hex');
  }
};
