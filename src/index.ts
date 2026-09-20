export { publicKeyToAddress, toChecksumAddress, isChecksumValid, type Address } from './address.js'
export {
  SCHEME_ID,
  COMPRESSED_KEY_BYTES,
  META_ADDRESS_BYTES,
  encodeMetaAddress,
  decodeMetaAddress,
  type MetaAddressKeys,
} from './meta-address.js'
export {
  deriveSharedSecret,
  deriveStealthPublicKey,
  deriveStealthPrivateScalar,
  stealthAddressFrom,
  CURVE_ORDER,
  type SharedSecret,
} from './derive.js'
export {
  SECRET_KEY_BYTES,
  generateStealthKeys,
  keysFromPrivate,
  toScalar,
  scalarToPrivateKey,
  privateKeyToHex,
  type StealthKeyPair,
  type StealthKeys,
} from './keys.js'
export {
  createStealthPayment,
  checkAnnouncement,
  type StealthPayment,
  type AnnouncementCandidate,
  type StealthMatch,
} from './payment.js'
export {
  REGISTER_KEYS_SELECTOR,
  STEALTH_META_ADDRESS_OF_SELECTOR,
  encodeRegisterKeys,
  encodeStealthMetaAddressOf,
  decodeStealthMetaAddressOf,
} from './registry.js'
export {
  ANNOUNCE_SELECTOR,
  ANNOUNCEMENT_TOPIC,
  encodeAnnounce,
  decodeAnnouncementLog,
  type AnnounceInput,
  type RawLog,
  type DecodedAnnouncement,
} from './announcer.js'

export { lockKeys, unlockKeys, VAULT_ITERATIONS, type VaultBlob } from './vault.js'
export {
  permitDigest,
  signPermit,
  encodeSweep,
  encodeNoncesCall,
  encodeDomainSeparatorCall,
  type PermitTerms,
  type SignedPermit,
  type SweepCalls,
} from './permit.js'
export { hexToBytesLoose } from './abi.js'
export { deriveRequest, deriveRequests, requestEphemeralScalar, type PaymentRequest } from './request.js'
export {
  watchKeysFrom,
  encodeWatchKey,
  decodeWatchKey,
  watchRequest,
  watchRequests,
  type WatchKeys,
  type WatchedRequest,
} from './watch.js'
export {
  sealNotes,
  openNotes,
  checkNotes,
  NOTE_MAX_LENGTH,
  NOTES_MAX,
  type NoteBlob,
  type Notes,
} from './notes.js'
export {
  backupSheet,
  parsePrivateKey,
  fingerprint,
  walletFingerprint,
  checkTranscription,
  type BackupSheet,
  type TranscriptionResult,
} from './backup.js'
export {
  scopedViewingKey,
  deriveScope,
  keysForScope,
  scopeLabelBytes,
  SCOPE_LABEL_MAX_BYTES,
  type Scope,
} from './scope.js'
export { scopedWatchKeys } from './watch.js'
export {
  ringSign,
  ringVerify,
  ringKeyImage,
  sameSigner,
  type Ring,
  type RingSignature,
} from './ring.js'
export {
  proveControl,
  verifyControl,
  proveControlOfSet,
  verifyControlOfSet,
  provePayment,
  verifyPayment,
  type ControlProof,
  type PaymentProof,
} from './prove.js'
