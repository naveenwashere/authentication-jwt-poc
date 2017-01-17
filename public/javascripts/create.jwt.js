var fs = require('fs'); //npm install fs
var btoa = require('btoa'); //npm install btoa
var atob = require('atob'); //npm install atob
var utf8 = require('utf8'); //npm install utf8
var jose = require('node-jose'); //npm install node-jose
var jwt = require('jsonwebtoken'); //npm install jsonwebtoken

var newline = "\n";

var keystore = jose.JWK.createKeyStore();

const headers = {
  "algorithm": "RS256"
};

const payload = {
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true,
  "expiresIn": '600s'
};

var privateSignKey = {
  key: fs.readFileSync('<path_to>/private.pem'),
  passphrase: '<passphrase>'
};

var publicSignKey = {
  key: fs.readFileSync('<path_to>/public.pem'),
  passphrase: 'passphrase'
};

const jwtoken = jwt.sign(payload, privateSignKey, headers);
console.log('Actual JWT after Signing: \n' + jwtoken + newline);

//Now encrypt the entire token
function encrypt(key, options, plaintext) {
  return jose.JWE.createEncrypt(options, key)
      .update(plaintext)
      .final()
      .then(result => {
      console.log("Encrypted JW Token: \n" + result + newline);
  //Decrypt the token
  jose.JWE.createDecrypt(keystore)
    .decrypt(result)
    .then(decrypted => {
    console.log("Decrypted result: \n" + atob(jose.util.base64url.encode(decrypted.payload, "utf8")) + newline);
  //Validate Token Singature
  var jwtoken = atob(jose.util.base64url.encode(decrypted.payload, "utf8")).replace(/\"/g, "");
  jwt.verify(jwtoken, publicSignKey.key, {algorithm: 'RS256'}, function(err, decoded) {
    console.log('Token Received: ' + jwtoken + newline);
    if(err != null) {
      console.log('Errorrrr: ' + err + newline);
    }
    console.log("Verified Payload Signature: " + newline);
    console.log(decoded);
  });
}, error => {
    console.log(error + newline);
  });
}, error => {
    console.log(error + newline);
  });
}

function rsa(compact) {
  keystore.generate("RSA", 2048, { kid: 'your-key' })
    .then(() => {
    const options = {
      format: compact ? 'compact' : 'general',
      contentAlg: 'A128CBC-HS256'
    };
  var publicKey = keystore.toJSON().keys[0];
  //console.log('KID: ' + keystore.get('your-key').toString + newline)
  return encrypt(keystore.toJSON().keys[0], options, JSON.stringify(jwtoken));
});
}

rsa('compact');