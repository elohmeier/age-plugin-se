import XCTest

@testable import age_plugin_se

#if !os(Linux) && !os(Windows)
  import CryptoKit
#else
  import Crypto
#endif

// Identity used by IdentityV1Tests, with the application password marker
let passwordIdentity = { () -> String in
  let id = try! Bech32().decode(
    "AGE-PLUGIN-SE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHSRP8GPG")
  return Bech32().encode(hrp: id.hrp, data: Identity.applicationPasswordMarker + id.data)
}()

let passwordIdentityRecipient =
  "age1tag1qf0l9gks6x65ha077wq3w3u8fy02tpg3cd9w5j0jlgpfgqkcut2lwksa782"

/// Agent that requires the password "secret" for all keys (which are raw P-256 keys)
class DummyAgentClient: AgentClient {
  var unlocked = false
  var unlockRequests: [Data] = []

  func ecdh(key: Data, share: Data) throws -> Data {
    if !unlocked {
      throw AgentError.locked
    }
    let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: key)
    return try privateKey.sharedSecretFromKeyAgreement(
      with: try P256.KeyAgreement.PublicKey(x963Representation: share)
    ).withUnsafeBytes { Data($0) }
  }

  func unlock(key: Data, password: Data) throws {
    unlockRequests.append(password)
    if password != Data("secret".utf8) {
      throw AgentError.badPassword
    }
    unlocked = true
  }
}

final class ApplicationPasswordIdentityTests: XCTestCase {
  var stream = MemoryStream()
  var crypto = DummyCrypto()

  let recipientStanza = """
    -> recipient-stanza 0 p256tag NDTf9g BD7IeMpB4oX0CHt/Bc9xzk6x1K262zNxoUtfAikZa5T7aUSkQuuvOANb1o+BKtf/4/F++4nJgRQ0PgIyFJq8i88
    14bmQarAgrOM0M27KRHYp9RzNYlcv3pJgRm9sTCB08c
    """

  override func setUp() {
    stream = MemoryStream()
    crypto = DummyCrypto()
    crypto.requiredApplicationPassword = Data("secret".utf8)
  }

  func stanzas(_ stanzas: [Stanza]) -> String {
    let s = MemoryStream()
    for stanza in stanzas {
      stanza.writeTo(stream: s)
    }
    return s.output
  }

  var passwordRequest: Stanza {
    return Stanza(
      type: "request-secret",
      body: Data("Enter the password for \(passwordIdentityRecipient)".utf8))
  }

  let fileKey = Stanza(
    type: "file-key", args: ["0"], body: Data(base64RawEncoded: "AAAAAAAAAAAAAAAAAAAAAQ")!)

  func testIdentity() throws {
    let identity = try Identity(ageIdentity: passwordIdentity, crypto: crypto)
    XCTAssertTrue(identity.requiresApplicationPassword)
    XCTAssertEqual(passwordIdentityRecipient, identity.recipient.ageRecipient(type: .tag))
    XCTAssertEqual(passwordIdentity, identity.ageIdentity)
  }

  func testNoAgent() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    stream.add(
      input: """
        -> add-identity \(passwordIdentity)

        \(recipientStanza)
        -> done

        -> ok
        c2VjcmV0
        -> ok

        """)
    plugin.runIdentityV1()

    XCTAssertEqual(Data("secret".utf8), crypto.applicationPassword)
    XCTAssertEqual(
      stanzas([passwordRequest, fileKey, Stanza(type: "done")]), stream.output)
  }

  func testNoAgent_IncorrectPassword() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    stream.add(
      input: """
        -> add-identity \(passwordIdentity)

        \(recipientStanza)
        -> done

        -> ok
        d3Jvbmc
        -> ok

        -> ok
        c2VjcmV0
        -> ok

        """)
    plugin.runIdentityV1()

    XCTAssertEqual(
      stanzas([
        passwordRequest,
        Stanza(type: "msg", body: Data("Incorrect password, please try again".utf8)),
        passwordRequest, fileKey, Stanza(type: "done"),
      ]), stream.output)
  }

  func testNoAgent_Cancelled() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    stream.add(
      input: """
        -> add-identity \(passwordIdentity)

        \(recipientStanza)
        -> done

        -> fail

        -> ok

        """)
    plugin.runIdentityV1()

    XCTAssertEqual(
      stanzas([
        passwordRequest,
        Stanza(type: "msg", body: Data("password entry cancelled".utf8)),
        Stanza(type: "done"),
      ]), stream.output)
  }

  func testAgent_Unlocked() throws {
    let agent = DummyAgentClient()
    agent.unlocked = true
    let plugin = Plugin(crypto: crypto, stream: stream, agent: agent)
    stream.add(
      input: """
        -> add-identity \(passwordIdentity)

        \(recipientStanza)
        -> done

        -> ok

        """)
    plugin.runIdentityV1()

    XCTAssertEqual([], agent.unlockRequests)
    XCTAssertNil(crypto.applicationPassword)
    XCTAssertEqual(stanzas([fileKey, Stanza(type: "done")]), stream.output)
  }

  func testAgent_Locked() throws {
    let agent = DummyAgentClient()
    let plugin = Plugin(crypto: crypto, stream: stream, agent: agent)
    stream.add(
      input: """
        -> add-identity \(passwordIdentity)

        \(recipientStanza)
        -> done

        -> ok
        d3Jvbmc
        -> ok

        -> ok
        c2VjcmV0
        -> ok

        """)
    plugin.runIdentityV1()

    XCTAssertEqual([Data("wrong".utf8), Data("secret".utf8)], agent.unlockRequests)
    XCTAssertTrue(agent.unlocked)
    XCTAssertNil(crypto.applicationPassword)
    XCTAssertEqual(
      stanzas([
        passwordRequest,
        Stanza(type: "msg", body: Data("Incorrect password, please try again".utf8)),
        passwordRequest, fileKey, Stanza(type: "done"),
      ]), stream.output)
  }

  func testAgent_TooManyIncorrectPasswords() throws {
    let agent = DummyAgentClient()
    let plugin = Plugin(crypto: crypto, stream: stream, agent: agent)
    stream.add(
      input: """
        -> add-identity \(passwordIdentity)

        \(recipientStanza)
        -> done

        -> ok
        d3Jvbmc
        -> ok

        -> ok
        d3Jvbmc
        -> ok

        -> ok
        d3Jvbmc
        -> ok

        """)
    plugin.runIdentityV1()

    XCTAssertEqual(3, agent.unlockRequests.count)
    XCTAssertEqual(
      stanzas([
        passwordRequest,
        Stanza(type: "msg", body: Data("Incorrect password, please try again".utf8)),
        passwordRequest,
        Stanza(type: "msg", body: Data("Incorrect password, please try again".utf8)),
        passwordRequest,
        Stanza(type: "msg", body: Data("incorrect password".utf8)),
        Stanza(type: "done"),
      ]), stream.output)
  }

  func testGenerate() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    let result = try plugin.generateKey(
      accessControl: .applicationPassword, recipientType: .tag,
      now: Date(timeIntervalSinceReferenceDate: -1_000_000_000),
      applicationPassword: Data("secret".utf8))
    XCTAssertEqual(Data("secret".utf8), crypto.applicationPassword)
    XCTAssertTrue(result.0.contains("# access control: application password\n"))
    let identityLine = result.0.split(separator: "\n").last { $0.hasPrefix("AGE-PLUGIN-SE-") }!
    let identity = try Identity(ageIdentity: String(identityLine), crypto: crypto)
    XCTAssertTrue(identity.requiresApplicationPassword)
    XCTAssertEqual(result.1, identity.recipient.ageRecipient(type: .tag))
  }

  func testGenerate_MissingPassword() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    XCTAssertThrowsError(
      try plugin.generateKey(accessControl: .applicationPassword, recipientType: .tag, now: Date())
    ) { error in
      XCTAssertEqual(error as! Plugin.Error, Plugin.Error.applicationPasswordMissing)
    }
  }

  func testGenerate_PQ() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    XCTAssertThrowsError(
      try plugin.generateKey(
        accessControl: .applicationPassword, recipientType: .tag, now: Date(), pq: true,
        applicationPassword: Data("secret".utf8))
    ) { error in
      XCTAssertEqual(error as! Plugin.Error, Plugin.Error.applicationPasswordPQ)
    }
  }
}

/// Key store that requires the password "secret" for all keys (which are raw P-256 keys)
class DummyKeyStore: AgentKeyStore {
  var unavailable = false

  func authorize(key: Data, password: Data) throws -> AnyObject {
    if unavailable {
      throw AgentError.unavailable("unavailable")
    }
    if password != Data("secret".utf8) {
      throw AgentError.badPassword
    }
    return NSObject()
  }

  func sharedSecret(key: Data, authorization: AnyObject, share: P256.KeyAgreement.PublicKey)
    throws -> Data
  {
    if unavailable {
      throw AgentError.unavailable("unavailable")
    }
    return try P256.KeyAgreement.PrivateKey(rawRepresentation: key)
      .sharedSecretFromKeyAgreement(with: share).withUnsafeBytes { Data($0) }
  }
}

final class AgentStateTests: XCTestCase {
  let key = P256.KeyAgreement.PrivateKey()
  let share = P256.KeyAgreement.PrivateKey().publicKey
  var now = Date(timeIntervalSinceReferenceDate: 0)

  func ecdh(_ state: AgentState) -> AgentResponse {
    return state.handle(
      AgentRequest(op: "ecdh", key: key.rawRepresentation, share: share.x963Representation))
  }

  func unlock(_ state: AgentState, _ password: String) -> AgentResponse {
    return state.handle(
      AgentRequest(op: "unlock", key: key.rawRepresentation, password: Data(password.utf8)))
  }

  func testUnlock() throws {
    let state = AgentState(keyStore: DummyKeyStore())
    XCTAssertEqual("locked", ecdh(state).error)
    XCTAssertEqual("bad-password", unlock(state, "wrong").error)
    XCTAssertEqual(0, state.handle(AgentRequest(op: "status")).unlocked)
    XCTAssertTrue(unlock(state, "secret").ok)
    XCTAssertEqual(1, state.handle(AgentRequest(op: "status")).unlocked)
    XCTAssertEqual(
      try key.sharedSecretFromKeyAgreement(with: share).withUnsafeBytes { Data($0) },
      ecdh(state).secret)
  }

  func testLock() throws {
    let state = AgentState(keyStore: DummyKeyStore())
    XCTAssertTrue(unlock(state, "secret").ok)
    XCTAssertTrue(state.handle(AgentRequest(op: "lock")).ok)
    XCTAssertEqual("locked", ecdh(state).error)
  }

  func testUnavailable() throws {
    let keyStore = DummyKeyStore()
    let state = AgentState(keyStore: keyStore)
    XCTAssertTrue(unlock(state, "secret").ok)
    keyStore.unavailable = true
    XCTAssertEqual("unavailable", ecdh(state).error)
    XCTAssertEqual("unavailable", unlock(state, "secret").error)
    keyStore.unavailable = false
    // Still unlocked afterwards
    XCTAssertTrue(ecdh(state).ok)
  }

  func testTimeout() throws {
    let state = AgentState(keyStore: DummyKeyStore(), timeout: 60, now: { self.now })
    XCTAssertTrue(unlock(state, "secret").ok)
    now += 59
    XCTAssertTrue(ecdh(state).ok)
    now += 2
    XCTAssertEqual("locked", ecdh(state).error)
  }

  func testInvalidRequests() throws {
    let state = AgentState(keyStore: DummyKeyStore())
    XCTAssertEqual("invalid", state.handle(AgentRequest(op: "frobnicate")).error)
    XCTAssertEqual("invalid", state.handle(AgentRequest(op: "unlock")).error)
    XCTAssertEqual(
      "invalid",
      state.handle(AgentRequest(op: "ecdh", key: key.rawRepresentation, share: Data([4]))).error)
  }

  func testWireFormat() throws {
    let request = try JSONDecoder().decode(
      AgentRequest.self, from: Data(#"{"op":"unlock","key":"AAE=","password":"cHc="}"#.utf8))
    XCTAssertEqual(
      AgentRequest(op: "unlock", key: Data([0, 1]), password: Data("pw".utf8)), request)
    let encoder = JSONEncoder()
    encoder.outputFormatting = .sortedKeys
    XCTAssertEqual(
      #"{"error":"locked","message":"key is locked","ok":false}"#,
      String(decoding: try encoder.encode(AgentResponse(error: .locked)), as: UTF8.self))
  }
}
