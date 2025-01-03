import {BigInteger, parseBigInt, RSAKey} from "./jsbn.js"
import sjcl from "./sjcl.mjs"

export enum KeyPairType {
    RSA,
    RSA_AND_ECC,
    TUTA_CRYPT,
}

const RSA_KEY_LENGTH_BITS = 2048
const RSA_PUBLIC_EXPONENT = 65537

function rsaDecrypt(privateKey, bytes) {
    try {
        const rsa = new RSAKey();
        // we have double conversion from bytes to hex to big int because there is no direct conversion from bytes to big int
        // BigInteger of JSBN uses a signed byte array and we convert to it by using Int8Array
        rsa.n = new BigInteger(new Int8Array(base64ToUint8Array(privateKey.modulus)));
        rsa.d = new BigInteger(new Int8Array(base64ToUint8Array(privateKey.privateExponent)));
        rsa.p = new BigInteger(new Int8Array(base64ToUint8Array(privateKey.primeP)));
        rsa.q = new BigInteger(new Int8Array(base64ToUint8Array(privateKey.primeQ)));
        rsa.dmp1 = new BigInteger(new Int8Array(base64ToUint8Array(privateKey.primeExponentP)));
        rsa.dmq1 = new BigInteger(new Int8Array(base64ToUint8Array(privateKey.primeExponentQ)));
        rsa.coeff = new BigInteger(new Int8Array(base64ToUint8Array(privateKey.crtCoefficient)));
        const hex = uint8ArrayToHex(bytes);
        const bigInt = parseBigInt(hex, 16);
        const decrypted = new Uint8Array(rsa.doPrivate(bigInt).toByteArray());
        // the decrypted value might have leading zeros or needs to be padded with zeros
        const paddedDecrypted = _padAndUnpadLeadingZeros(privateKey.keyLength / 8 - 1, decrypted);
        return oaepUnpad(paddedDecrypted, privateKey.keyLength);
    } catch (e) {
        throw new Error("failed RSA decryption");
    }
}

export function rsaEncrypt(publicKey: RsaPublicKey, bytes: Uint8Array, seed: Uint8Array): Uint8Array {
    const rsa = new RSAKey()
    // we have double conversion from bytes to hex to big int because there is no direct conversion from bytes to big int
    // BigInteger of JSBN uses a signed byte array and we convert to it by using Int8Array
    rsa.n = new BigInteger(new Int8Array(base64ToUint8Array(publicKey.modulus)))
    rsa.e = publicKey.publicExponent
    const paddedBytes = oaepPad(bytes, publicKey.keyLength, seed)
    const paddedHex = uint8ArrayToHex(paddedBytes)
    const bigInt = parseBigInt(paddedHex, 16)
    let encrypted

    try {
        // toByteArray() produces Array so we convert it to buffer.
        encrypted = new Uint8Array(rsa.doPublic(bigInt).toByteArray())
    } catch (e) {
        throw new Error("failed RSA encryption")
    }

    // the encrypted value might have leading zeros or needs to be padded with zeros
    return _padAndUnpadLeadingZeros(publicKey.keyLength / 8, encrypted)
}

export function oaepPad(value: Uint8Array, keyLength: number, seed: Uint8Array): Uint8Array {
    let hashLength = 32 // bytes sha256

    if (seed.length !== hashLength) {
        throw new Error("invalid seed length: " + seed.length + ". expected: " + hashLength + " bytes!")
    }

    if (value.length > keyLength / 8 - hashLength - 1) {
        throw new Error("invalid value length: " + value.length + ". expected: max. " + (keyLength / 8 - hashLength - 1))
    }

    let block = _getPSBlock(value, keyLength)

    let dbMask = mgf1(seed, block.length - hashLength)

    for (let i = hashLength; i < block.length; i++) {
        block[i] ^= dbMask[i - hashLength]
    }

    // same as invoking sha256 directly because only one block is hashed
    let seedMask = mgf1(block.slice(hashLength, block.length), hashLength)

    for (let i = 0; i < seedMask.length; i++) {
        block[i] = seed[i] ^ seedMask[i]
    }

    return block
}

export function _getPSBlock(value: Uint8Array, keyLength: number): Uint8Array {
    let hashLength = 32 // bytes sha256

    let blockLength = keyLength / 8 - 1 // the leading byte shall be 0 to make the resulting value in any case smaller than the modulus, so we just leave the byte off

    let block = new Uint8Array(blockLength)
    let defHash = sha256Hash(new Uint8Array([])) // empty label

    let nbrOfZeros = block.length - (1 + value.length)

    for (let i = 0; i < block.length; i++) {
        if (i >= hashLength && i < 2 * hashLength) {
            block[i] = defHash[i - hashLength]
        } else if (i < nbrOfZeros) {
            block[i] = 0
        } else if (i === nbrOfZeros) {
            block[i] = 1
        } else {
            block[i] = value[i - nbrOfZeros - 1]
        }
    }

    return block
}

/**
 * Converts the given BitArray (SJCL) to an Uint8Array.
 * @param bits The BitArray.
 * @return The uint8array.
 */
export function bitArrayToUint8Array(bits: BitArray): Uint8Array {
    return new Uint8Array(sjcl.codec.arrayBuffer.fromBits(bits, false))
}

function base64ToUint8Array(base64: string): Uint8Array {
    if (base64.length % 4 !== 0) {
        throw new Error(`invalid base64 length: ${base64} (${base64.length})`)
    }

    const binaryString = atob(base64)
    const result = new Uint8Array(binaryString.length)

    for (let i = 0; i < binaryString.length; i++) {
        result[i] = binaryString.charCodeAt(i)
    }

    return result
}

const hexDigits = "0123456789abcdef"

type Hex = string

function uint8ArrayToHex(uint8Array: Uint8Array): Hex {
    let hex = ""

    for (let i = 0; i < uint8Array.byteLength; i++) {
        let value = uint8Array[i]
        hex += hexDigits[value >> 4] + hexDigits[value & 15]
    }

    return hex
}

export const KEY_LENGTH_BYTES_AES_256 = 32

export function aes256RandomKey() {
    const randomData = new Uint8Array(KEY_LENGTH_BYTES_AES_256)
    crypto.getRandomValues(randomData)
    return randomData
}

function _padAndUnpadLeadingZeros(targetByteLength: number, byteArray: Uint8Array): Uint8Array {
    const result = new Uint8Array(targetByteLength)

    // JSBN produces results which are not always exact length.
    // The byteArray might have leading 0 that make it larger than the actual result array length.
    // Here we cut them off
    // byteArray [0, 0, 1, 1, 1]
    // target       [0, 0, 0, 0]
    // result       [0, 1, 1, 1]
    if (byteArray.length > result.length) {
        const lastExtraByte = byteArray[byteArray.length - result.length - 1]

        if (lastExtraByte !== 0) {
            throw new Error(`leading byte is not 0 but ${lastExtraByte}, encrypted length: ${byteArray.length}`)
        }

        byteArray = byteArray.slice(byteArray.length - result.length)
    }

    // If the byteArray is not as long as the result array we add leading 0's
    // byteArray     [1, 1, 1]
    // target     [0, 0, 0, 0]
    // result     [0, 1, 1, 1]
    result.set(byteArray, result.length - byteArray.length)
    return result
}

function oaepUnpad(value: Uint8Array, keyLength: number): Uint8Array {
    let hashLength = 32 // bytes sha256

    if (value.length !== keyLength / 8 - 1) {
        throw new Error("invalid value length: " + value.length + ". expected: " + (keyLength / 8 - 1) + " bytes!")
    }

    let seedMask = mgf1(value.slice(hashLength, value.length), hashLength)
    let seed = new Uint8Array(hashLength)

    for (let i = 0; i < seedMask.length; i++) {
        seed[i] = value[i] ^ seedMask[i]
    }

    let dbMask = mgf1(seed, value.length - hashLength)

    for (let i = hashLength; i < value.length; i++) {
        value[i] ^= dbMask[i - hashLength]
    }

    // check that the zeros and the one is there
    for (var index = 2 * hashLength; index < value.length; index++) {
        if (value[index] === 1) {
            // found the 0x01
            break
        } else if (value[index] !== 0 || index === value.length) {
            throw new Error("invalid padding")
        }
    }

    return value.slice(index + 1, value.length)
}

/**
 * @param seed An array of byte values.
 * @param length The length of the return value in bytes.
 */
function mgf1(seed: Uint8Array, length: number): Uint8Array {
    let C: Uint8Array | null = null
    let counter = 0
    let T = new Uint8Array(0)

    do {
        C = i2osp(counter)
        T = concat(T, sha256Hash(concat(seed, C)))
    } while (++counter < Math.ceil(length / (256 / 8)))

    return T.slice(0, length)
}

function i2osp(i: number): Uint8Array {
    return new Uint8Array([(i >> 24) & 255, (i >> 16) & 255, (i >> 8) & 255, (i >> 0) & 255])
}


/**
 * Create the hash of the given data.
 * @param uint8Array The bytes.
 * @return The hash.
 */
export function sha256Hash(uint8Array: Uint8Array): Uint8Array {
    const sha256 = new sjcl.hash.sha256()
    try {
        sha256.update(sjcl.codec.arrayBuffer.toBits(uint8Array.buffer, uint8Array.byteOffset, uint8Array.byteLength))
        return new Uint8Array(sjcl.codec.arrayBuffer.fromBits(sha256.finalize(), false))
    } finally {
        sha256.reset()
    }
}

export function concat(...arrays: Uint8Array[]): Uint8Array {
    let length = arrays.reduce((previous, current) => previous + current.length, 0)
    let result = new Uint8Array(length)
    let index = 0
    for (const array of arrays) {
        result.set(array, index)
        index += array.length
    }
    return result
}

export function hexToRsaPrivateKey(privateKeyHex: Hex): RsaPrivateKey {
    return _arrayToPrivateKey(_hexToKeyArray(privateKeyHex))
}

export function hexToRsaPublicKey(publicKeyHex: Hex): RsaPublicKey {
    return _arrayToPublicKey(_hexToKeyArray(publicKeyHex))
}

function _hexToKeyArray(hex: Hex): BigInteger[] {
    try {
        var key: BigInteger[] = []
        var pos = 0

        while (pos < hex.length) {
            var nextParamLen = parseInt(hex.substring(pos, pos + 4), 16)
            pos += 4
            key.push(parseBigInt(hex.substring(pos, pos + nextParamLen), 16))
            pos += nextParamLen
        }

        _validateKeyLength(key)

        return key
    } catch (e) {
        throw new Error("hex to rsa key failed")
    }
}

function _arrayToPublicKey(publicKey: BigInteger[]): RsaPublicKey {
    return {
        keyPairType: KeyPairType.RSA,
        version: 0,
        keyLength: RSA_KEY_LENGTH_BITS,
        modulus: int8ArrayToBase64(new Int8Array(publicKey[0].toByteArray())),
        publicExponent: RSA_PUBLIC_EXPONENT,
    }
}

function _validateKeyLength(key: BigInteger[]) {
    if (key.length !== 1 && key.length !== 7) {
        throw new Error("invalid key params")
    }

    if (key[0].bitLength() < RSA_KEY_LENGTH_BITS - 1 || key[0].bitLength() > RSA_KEY_LENGTH_BITS) {
        throw new Error("invalid key length, expected: around " + RSA_KEY_LENGTH_BITS + ", but was: " + key[0].bitLength())
    }
}

function _arrayToPrivateKey(privateKey: BigInteger[]): RsaPrivateKey {
    return {
        version: 0,
        keyLength: RSA_KEY_LENGTH_BITS,
        modulus: int8ArrayToBase64(new Int8Array(privateKey[0].toByteArray())),
        privateExponent: int8ArrayToBase64(new Int8Array(privateKey[1].toByteArray())),
        primeP: int8ArrayToBase64(new Int8Array(privateKey[2].toByteArray())),
        primeQ: int8ArrayToBase64(new Int8Array(privateKey[3].toByteArray())),
        primeExponentP: int8ArrayToBase64(new Int8Array(privateKey[4].toByteArray())),
        primeExponentQ: int8ArrayToBase64(new Int8Array(privateKey[5].toByteArray())),
        crtCoefficient: int8ArrayToBase64(new Int8Array(privateKey[6].toByteArray())),
    }
}


export type AsymmetricKeyPair = RsaKeyPair

export type AbstractKeyPair = {
    keyPairType: KeyPairType
}
export type AbstractPublicKey = {
    keyPairType: KeyPairType
}


type Base64 = string

export type RsaKeyPair = AbstractKeyPair & {
    publicKey: RsaPublicKey
    privateKey: RsaPrivateKey
}
export type RsaPrivateKey = {
    version: number
    keyLength: number
    modulus: Base64
    privateExponent: Base64
    primeP: Base64
    primeQ: Base64
    primeExponentP: Base64
    primeExponentQ: Base64
    crtCoefficient: Base64
}
export type RsaPublicKey = AbstractPublicKey & {
    version: number
    keyLength: number
    modulus: Base64
    publicExponent: number
}

export function int8ArrayToBase64(bytes: Int8Array): Base64 {
    // Values 0 to 127 are the same for signed and unsigned bytes
    // and -128 to -1 are mapped to the same chars as 128 to 255.
    let converted = new Uint8Array(bytes)
    return uint8ArrayToBase64(converted)
}


/**
 * Converts an Uint8Array to a Base64 encoded string.
 *
 * @param bytes The bytes to convert.
 * @return The Base64 encoded string.
 */
export function uint8ArrayToBase64(bytes: Uint8Array): Base64 {
    if (bytes.length < 512) {
        // Apply fails on big arrays fairly often. We tried it with 60000 but if you're already
        // deep in the stack than we cannot allocate such a big argument array.
        return btoa(String.fromCharCode(...bytes))
    }

    let binary = ""
    const len = bytes.byteLength

    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i])
    }

    return btoa(binary)
}


const privateKey = hexToRsaPrivateKey(
    "02008bb1bbcb2c6915c182b0c7cc93e1d8210181ffee4be4ae81f7a98fdba2d6e37cea72e2124ebb6b05d330ab1ddfbc6d85c9d1c90fc3b65bd9634c3b722fe77ab98f33cc28af975d51609e1c308324501d615cbb82836c33c2a240e00826ddf09460cee7a975c0607579d4f7b707e19287a1c754ba485e04aab664e44cae8fcab770b9bb5c95a271786aa79d6fa11dd21bdb3a08b679bd5f29fc95ab573a3dabcbd8e70aaec0cc2a817eefbc886d3eafea96abd0d5e364b83ccf74f4d18b3546b014fa24b90134179ed952209971211c623a2743da0c3236abd512499920a75651482b43b27c18d477e8735935425933d8f09a12fbf1950cf8a381ef5f2400fcf90200816022249104e1f94e289b6284b36d8f63ee1a31806852965be0d632fc25389ac02795e88eb254f4181bc2def00f7affa5627d6bf43e37e2a56c3cc20c4bbe058cf2d3e9fa759d1f78f3f5f797fd5195644e95fad1ecac235e51e72aa59476f374952b486e9db4b818157d362e3e638ee9edca329c4336df43fd3cd327f8542d1add9798af1d6a9e8cf8f54dd0b6a6f9ed9c3f5d803c220716757871e1442ef407ffe5df44c364bf57a60551b681173747b8df8e4138101f1d048cc1941a5d4c1fd3eda5bc96496eb1892477d811b845a7c9b3333e700989a1134e8f65edbf3a8332baa7195eb6aa33591b6ab41ec8215c6487979df5cf1b9736fd4fea73eee102000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e7a2e7a5cc651614fd17eb10765ef63462e5767745fc849e97095319d42f8cbb1485aba0f590b33208e666e949db0465e483a122467f771a986da6855abb148d0b5c1eefb08636d0aeb36b8ec161497cc9a64704f0976aceb33d09af5408ded1aec771b534f9a27fd9dc3303146ce98872915ed730ed9661eec46b8c0d6b6d37020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009a632cb2e0a17ee6e363e3e056e5170480a3790023e342cb221431be37d63e692ce572390a379cf470c8a9fa4251a0af84d746b79ff91f6dcf168417137150d93049098ef747a601825982cbbd1ac1c20b3f3ee97b25e1739c31b43e78fc1cd53134dc4e82ebf98c720c34852fbd2288370421b848575f4d054e1d1e66b47f4f02000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b09e8b48e56fd2859072135f4b129f62546228914b80fed239d1f756436f3a3c4faa98b2336bf0e6ded86771cc49beb1beab0b4b2a3bf8e20385e029e083b368d4579a9322a343da9ccadbe14edc527f5ef6754273fcd088e92c4a5d30934eeaccfcf05bbe17f66acc0055b92c72db229a50f3e2db40dda0b0c17e4b9cd3e3c30200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000088861ee6e7e1a7f8c1287a40ce56b3ae159b79caf7f166057fd35fd1984aead1d313eb982942d897088d4a52b606bd13b9632d7400112b0bcdcf596b9693e42ccb982acdb43a35c0abe63fd5af1a54312604fdbb365d5f2afefaad2b798d6869d6a3aa15fb8c75170f5b5fae4f72ef7089462c136c55673f12ebeab0119e97dd02000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d8538fe6ebe9514412692fc985f8fd62b237c51c160c3d49aeeafffa057f2feff8f29040a205895b61dfa3f6188851021dc9e50152f3ea69746f5eb491af4a6dde21db9fa2c6fa61198ea02d6b600ed4267c3871af686c8db12e4bcbaaaa552e157e66fda90d34fce11cfd0f5eea6fbb236818070fb3a13751ad408e4231f499",
)
const publicKey = hexToRsaPublicKey(
    "02008bb1bbcb2c6915c182b0c7cc93e1d8210181ffee4be4ae81f7a98fdba2d6e37cea72e2124ebb6b05d330ab1ddfbc6d85c9d1c90fc3b65bd9634c3b722fe77ab98f33cc28af975d51609e1c308324501d615cbb82836c33c2a240e00826ddf09460cee7a975c0607579d4f7b707e19287a1c754ba485e04aab664e44cae8fcab770b9bb5c95a271786aa79d6fa11dd21bdb3a08b679bd5f29fc95ab573a3dabcbd8e70aaec0cc2a817eefbc886d3eafea96abd0d5e364b83ccf74f4d18b3546b014fa24b90134179ed952209971211c623a2743da0c3236abd512499920a75651482b43b27c18d477e8735935425933d8f09a12fbf1950cf8a381ef5f2400fcf9",
)

const RSA_TEST_KEYPAIR: RsaKeyPair = {keyPairType: KeyPairType.RSA, privateKey, publicKey}

const bucketKey = bitArrayToUint8Array(aes256RandomKey())

const keyPair = RSA_TEST_KEYPAIR
let seed = new Uint8Array(32)
crypto.getRandomValues(seed)

let pubEncBucketKey
const iterations = 1
for (let i = 0; i < iterations; i++) {
    pubEncBucketKey = rsaEncrypt(keyPair.publicKey, bucketKey, seed)
}
let decryptedBucketKey
for (let i = 0; i < iterations; i++) {
    decryptedBucketKey = rsaDecrypt(keyPair.privateKey, pubEncBucketKey)
}

// o(bucketKey).deepEquals(decryptedBucketKey)
console.log(uint8ArrayToBase64(bucketKey), uint8ArrayToBase64(decryptedBucketKey))
