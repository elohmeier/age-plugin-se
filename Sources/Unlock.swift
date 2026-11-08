import Foundation

#if !os(Linux) && !os(Windows)
  import CryptoKit
#else
  import Crypto
#endif

/// Client side of the unlock agent (see AGENT.md)
protocol AgentClient {
  func ecdh(key: Data, share: Data) throws -> Data
  func unlock(key: Data, password: Data) throws
}

enum AgentError: LocalizedError, Equatable {
  case locked
  case badPassword
  case unavailable(String)
  case invalid(String)
  case `internal`(String)

  var code: String {
    switch self {
    case .locked: return "locked"
    case .badPassword: return "bad-password"
    case .unavailable: return "unavailable"
    case .invalid: return "invalid"
    case .internal: return "internal"
    }
  }

  init(code: String, message: String) {
    switch code {
    case "locked": self = .locked
    case "bad-password": self = .badPassword
    case "unavailable": self = .unavailable(message)
    case "invalid": self = .invalid(message)
    default: self = .internal(message)
    }
  }

  public var errorDescription: String? {
    switch self {
    case .locked: return "key is locked"
    case .badPassword: return "incorrect password"
    case .unavailable(let message): return message
    case .invalid(let message): return "invalid agent request: \(message)"
    case .internal(let message): return "agent error: \(message)"
    }
  }
}

/// Authorizes key agreement for keys protected by an application password.
///
/// If an agent is running, the agent performs the key agreement, and is unlocked on first use.
/// Otherwise, the password is asked once per key for the lifetime of the plugin process.
class ApplicationPasswordUnlocker {
  static let maxAttempts = 3

  let crypto: Crypto
  let agent: AgentClient?
  let requestPassword: (String) throws -> Data
  let displayMessage: (String) -> Void

  /// Key for which the crypto context currently holds the password
  private var authorizedKey: Data?

  init(
    crypto: Crypto, agent: AgentClient?, requestPassword: @escaping (String) throws -> Data,
    displayMessage: @escaping (String) -> Void
  ) {
    self.crypto = crypto
    self.agent = agent
    self.requestPassword = requestPassword
    self.displayMessage = displayMessage
  }

  func sharedSecret(
    key: SecureEnclaveP256PrivateKey, with share: P256.KeyAgreement.PublicKey
  ) throws -> Data {
    let keyData = key.dataRepresentation
    if let agent = agent {
      do {
        return try agent.ecdh(key: keyData, share: share.x963Representation)
      } catch AgentError.locked {
        try withPassword(for: key) { try agent.unlock(key: keyData, password: $0) }
        return try agent.ecdh(key: keyData, share: share.x963Representation)
      }
    }
    if authorizedKey == keyData {
      return try key.sharedSecretFromKeyAgreement(with: share)
    }
    var result = Data()
    try withPassword(for: key) {
      try crypto.setApplicationPassword($0)
      result = try key.sharedSecretFromKeyAgreement(with: share)
    }
    authorizedKey = keyData
    return result
  }

  /// Asks for the password of the key, and runs `body` with it until it doesn't throw.
  private func withPassword(for key: SecureEnclaveP256PrivateKey, body: (Data) throws -> Void)
    throws
  {
    let recipient = Recipient(p256PublicKey: key.publicKey).ageRecipient(type: .tag)
    for attempt in 1...ApplicationPasswordUnlocker.maxAttempts {
      let password = try requestPassword("Enter the password for \(recipient)")
      do {
        try body(password)
        return
      } catch let error as AgentError where error != .badPassword {
        throw error
      } catch {
        if attempt < ApplicationPasswordUnlocker.maxAttempts {
          displayMessage("Incorrect password, please try again")
        }
      }
    }
    throw Plugin.Error.incorrectApplicationPassword
  }
}

/// Secure Enclave key protected by an application password, unlocked on first use
struct ApplicationPasswordP256PrivateKey: SecureEnclaveP256PrivateKey {
  let key: SecureEnclaveP256PrivateKey
  let unlocker: ApplicationPasswordUnlocker

  var publicKey: P256.KeyAgreement.PublicKey {
    return key.publicKey
  }

  var dataRepresentation: Data {
    return key.dataRepresentation
  }

  func sharedSecretFromKeyAgreement(with publicKeyShare: P256.KeyAgreement.PublicKey) throws
    -> Data
  {
    return try unlocker.sharedSecret(key: key, with: publicKeyShare)
  }
}
