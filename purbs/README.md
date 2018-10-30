# PURB

## Encoding

// Cornerstone - 40 bytes
//  ______32____ ___8___
// | Public Key | Nonce |
//  –––––––––––– –––––––
//
// Entrypoint - 40 bytes
//  _______16______ _______4_______ ________4_______ _16__
// | Symmetric Key | Payload Start | Payload Length | MAC |
//  ––––––––––––––– ––––––––––––––– –––––––––––––––– –––––
//
// PURB
//  __12___ ________ ______________
// | Nonce | Header | Payload + MAC|
//  ––––––– –––––––– ––––––––––––––