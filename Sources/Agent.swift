import Foundation

#if !os(Linux) && !os(Windows)
  import CryptoKit
  import LocalAuthentication
#else
  import Crypto
#endif

/// Agent request (see AGENT.md). Binary values are base64 encoded by JSONEncoder.
struct AgentRequest: Codable, Equatable {
  var op: String
  var key: Data?
  var share: Data?
  var password: Data?
}

struct AgentResponse: Codable, Equatable {
  var ok: Bool
  var secret: Data?
  var unlocked: Int?
  var error: String?
  var message: String?

  init(ok: Bool = true, secret: Data? = nil, unlocked: Int? = nil) {
    self.ok = ok
    self.secret = secret
    self.unlocked = unlocked
  }

  init(error: AgentError) {
    self.ok = false
    self.error = error.code
    self.message = error.localizedDescription
  }
}

/// Performs key operations for the agent
protocol AgentKeyStore {
  /// Checks the password by using the key, and returns an authorization for later use.
  /// Throws `AgentError.badPassword` if the password is incorrect.
  func authorize(key: Data, password: Data) throws -> AnyObject

  func sharedSecret(key: Data, authorization: AnyObject, share: P256.KeyAgreement.PublicKey)
    throws -> Data
}

/// Password kept in locked (unswappable) memory, zeroed when released
final class SecretBuffer {
  private let pointer: UnsafeMutableRawPointer
  let count: Int

  init(_ data: Data) {
    count = data.count
    pointer = UnsafeMutableRawPointer.allocate(byteCount: max(count, 1), alignment: 1)
    mlock(pointer, max(count, 1))
    data.copyBytes(to: pointer.assumingMemoryBound(to: UInt8.self), count: count)
  }

  var data: Data {
    return Data(bytes: pointer, count: count)
  }

  deinit {
    memset_s(pointer, max(count, 1), 0, max(count, 1))
    munlock(pointer, max(count, 1))
    pointer.deallocate()
  }
}

/// Agent state: authorizations of unlocked keys
final class AgentState: @unchecked Sendable {
  struct Entry {
    var authorization: AnyObject
    /// Kept to recreate the authorization if the system invalidates it (e.g. around sleep)
    let password: SecretBuffer
    let unlockedAt: Date
  }

  let keyStore: AgentKeyStore
  let timeout: TimeInterval?
  let now: () -> Date
  let log: (String) -> Void
  private var entries: [Data: Entry] = [:]
  private let lock = NSLock()

  init(
    keyStore: AgentKeyStore, timeout: TimeInterval? = nil, now: @escaping () -> Date = Date.init,
    log: @escaping (String) -> Void = { FileHandle.standardError.write(Data("\($0)\n".utf8)) }
  ) {
    self.keyStore = keyStore
    self.timeout = timeout
    self.now = now
    self.log = log
  }

  func handle(_ request: AgentRequest) -> AgentResponse {
    lock.lock()
    defer { lock.unlock() }
    do {
      switch request.op {
      case "status":
        expire()
        return AgentResponse(unlocked: entries.count)
      case "lock":
        entries.removeAll()
        return AgentResponse()
      case "unlock":
        guard let key = request.key, let password = request.password else {
          throw AgentError.invalid("missing key or password")
        }
        let authorization = try keyStore.authorize(key: key, password: password)
        entries[AgentState.keyID(key)] = Entry(
          authorization: authorization, password: SecretBuffer(password), unlockedAt: now())
        return AgentResponse()
      case "ecdh":
        guard let key = request.key, let shareData = request.share else {
          throw AgentError.invalid("missing key or share")
        }
        guard let share = try? P256.KeyAgreement.PublicKey(x963Representation: shareData) else {
          throw AgentError.invalid("invalid share")
        }
        expire()
        let id = AgentState.keyID(key)
        guard let entry = entries[id] else {
          throw AgentError.locked
        }
        do {
          return AgentResponse(
            secret: try keyStore.sharedSecret(
              key: key, authorization: entry.authorization, share: share))
        } catch let error as AgentError {
          // The key cannot be used right now (e.g. the Mac is locked), but stays unlocked
          log("key agreement failed: \(error.localizedDescription)")
          throw error
        } catch {
          // The system may have invalidated the authorization: recreate it from the password
          log("key agreement failed, reauthorizing: \(error)")
          let authorization: AnyObject
          do {
            authorization = try keyStore.authorize(key: key, password: entry.password.data)
          } catch AgentError.badPassword {
            log("password no longer accepted, locking key")
            entries[id] = nil
            throw AgentError.locked
          }
          entries[id]?.authorization = authorization
          return AgentResponse(
            secret: try keyStore.sharedSecret(key: key, authorization: authorization, share: share)
          )
        }
      default:
        throw AgentError.invalid("unknown operation `\(request.op)`")
      }
    } catch let error as AgentError {
      return AgentResponse(error: error)
    } catch {
      return AgentResponse(error: .internal(error.localizedDescription))
    }
  }

  func lockAll() {
    lock.lock()
    defer { lock.unlock() }
    entries.removeAll()
  }

  private func expire() {
    guard let timeout = timeout else {
      return
    }
    let now = self.now()
    entries = entries.filter { now.timeIntervalSince($0.value.unlockedAt) < timeout }
  }

  static func keyID(_ key: Data) -> Data {
    return Data(SHA256.hash(data: key))
  }
}

#if os(macOS)
  /// Key operations on Secure Enclave keys protected by an application password.
  /// The authorization is an `LAContext` holding the password.
  struct SecureEnclaveKeyStore: AgentKeyStore {
    func authorize(key: Data, password: Data) throws -> AnyObject {
      let context = LAContext()
      context.interactionNotAllowed = true
      if !context.setCredential(password, type: .applicationPassword) {
        throw AgentError.internal("unable to set application password")
      }
      let privateKey: SecureEnclave.P256.KeyAgreement.PrivateKey
      do {
        privateKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
          dataRepresentation: key, authenticationContext: context)
      } catch {
        throw AgentError.invalid("invalid key: \(error.localizedDescription)")
      }
      do {
        let _: SharedSecret = try privateKey.sharedSecretFromKeyAgreement(
          with: P256.KeyAgreement.PrivateKey().publicKey)
      } catch {
        if let unavailable = SecureEnclaveKeyStore.unavailableError(error) {
          throw unavailable
        }
        // An incorrect application password fails the operation in CryptoTokenKit
        let nsError = error as NSError
        if nsError.domain == "CryptoTokenKit" && nsError.code == -3 {
          throw AgentError.badPassword
        }
        throw AgentError.internal("\(error)")
      }
      return context
    }

    /// Keys that are only accessible when the Mac is unlocked fail with
    /// errSecInteractionNotAllowed while it is locked, regardless of the password.
    static func unavailableError(_ error: Error) -> AgentError? {
      let error = error as NSError
      if error.domain == NSOSStatusErrorDomain && error.code == Int(errSecInteractionNotAllowed) {
        return .unavailable("Secure Enclave key cannot be used while the Mac is locked")
      }
      return nil
    }

    func sharedSecret(key: Data, authorization: AnyObject, share: P256.KeyAgreement.PublicKey)
      throws -> Data
    {
      do {
        let privateKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
          dataRepresentation: key, authenticationContext: authorization as? LAContext)
        let sharedSecret: SharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: share)
        return sharedSecret.withUnsafeBytes { Data($0) }
      } catch {
        throw SecureEnclaveKeyStore.unavailableError(error) ?? error
      }
    }
  }

  enum AgentSocket {
    static let maxMessageSize = 64 * 1024

    static var defaultPath: String {
      if let path = ProcessInfo.processInfo.environment["AGE_PLUGIN_SE_AGENT_SOCK"], !path.isEmpty {
        return path
      }
      return FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/age-plugin-se/agent.sock").path
    }

    static func address(_ path: String) throws -> sockaddr_un {
      var address = sockaddr_un()
      address.sun_family = sa_family_t(AF_UNIX)
      let pathBytes = Array(path.utf8)
      let capacity = MemoryLayout.size(ofValue: address.sun_path)
      if pathBytes.count >= capacity {
        throw AgentError.internal("socket path too long: \(path)")
      }
      withUnsafeMutableBytes(of: &address.sun_path) { buffer in
        buffer.copyBytes(from: pathBytes)
      }
      address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
      return address
    }

    static func withSockaddr<T>(
      _ address: inout sockaddr_un, _ body: (UnsafePointer<sockaddr>, socklen_t) -> T
    ) -> T {
      return withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
          body($0, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
      }
    }

    /// Refuses socket directories that other users could have planted a socket in
    static func checkDirectory(_ path: String) throws {
      let directory = (path as NSString).deletingLastPathComponent
      var info = stat()
      if stat(directory, &info) != 0 {
        throw AgentError.internal("cannot access \(directory)")
      }
      if info.st_uid != getuid() || info.st_mode & 0o022 != 0 {
        throw AgentError.internal(
          "\(directory) must be owned by the current user, and not writable by others")
      }
    }

    static func setTimeout(_ fd: Int32, seconds: Int) {
      var timeout = timeval(tv_sec: seconds, tv_usec: 0)
      let size = socklen_t(MemoryLayout<timeval>.size)
      setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, size)
      setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, size)
    }

    /// Reads up to (and excluding) the first newline
    static func readLine(_ fd: Int32) throws -> Data {
      var result = Data()
      var buffer = [UInt8](repeating: 0, count: 4096)
      while true {
        let n = read(fd, &buffer, buffer.count)
        if n < 0 {
          throw AgentError.internal("read failed: \(String(cString: strerror(errno)))")
        }
        if n == 0 {
          return result
        }
        if let newline = buffer[..<n].firstIndex(of: 0x0a) {
          result.append(contentsOf: buffer[..<newline])
          return result
        }
        result.append(contentsOf: buffer[..<n])
        if result.count > maxMessageSize {
          throw AgentError.invalid("message too large")
        }
      }
    }

    static func writeAll(_ fd: Int32, _ data: Data) throws {
      try data.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) in
        var offset = 0
        while offset < buffer.count {
          let n = write(fd, buffer.baseAddress! + offset, buffer.count - offset)
          if n <= 0 {
            throw AgentError.internal("write failed: \(String(cString: strerror(errno)))")
          }
          offset += n
        }
      }
    }
  }

  /// Agent client over a Unix socket
  final class UnixSocketAgentClient: AgentClient {
    let path: String

    init(path: String = AgentSocket.defaultPath) {
      self.path = path
    }

    /// Returns a client if an agent is listening, and the agent is not disabled
    static func available() -> UnixSocketAgentClient? {
      if let disabled = ProcessInfo.processInfo.environment["AGE_PLUGIN_NO_AGENT"],
        !disabled.isEmpty
      {
        return nil
      }
      let client = UnixSocketAgentClient()
      return (try? client.status()) != nil ? client : nil
    }

    func request(_ request: AgentRequest) throws -> AgentResponse {
      let fd = socket(AF_UNIX, SOCK_STREAM, 0)
      if fd < 0 {
        throw AgentError.internal("socket failed")
      }
      defer { close(fd) }
      try AgentSocket.checkDirectory(path)
      var address = try AgentSocket.address(path)
      let result = AgentSocket.withSockaddr(&address) { connect(fd, $0, $1) }
      if result != 0 {
        throw AgentError.internal("cannot connect to agent at \(path)")
      }
      AgentSocket.setTimeout(fd, seconds: 30)
      try AgentSocket.writeAll(fd, try JSONEncoder().encode(request) + Data([0x0a]))
      let response = try JSONDecoder().decode(
        AgentResponse.self, from: try AgentSocket.readLine(fd))
      if !response.ok {
        throw AgentError(code: response.error ?? "", message: response.message ?? "")
      }
      return response
    }

    func ecdh(key: Data, share: Data) throws -> Data {
      guard let secret = try request(AgentRequest(op: "ecdh", key: key, share: share)).secret
      else {
        throw AgentError.internal("missing secret in response")
      }
      return secret
    }

    func unlock(key: Data, password: Data) throws {
      _ = try request(AgentRequest(op: "unlock", key: key, password: password))
    }

    func lock() throws {
      _ = try request(AgentRequest(op: "lock"))
    }

    func status() throws -> Int {
      return try request(AgentRequest(op: "status")).unlocked ?? 0
    }
  }

  /// Agent server over a Unix socket
  final class AgentServer: @unchecked Sendable {
    let path: String
    let state: AgentState

    init(path: String, state: AgentState) {
      self.path = path
      self.state = state
    }

    /// Binds the socket, and serves requests on a background thread
    func start() throws {
      let directory = (path as NSString).deletingLastPathComponent
      try FileManager.default.createDirectory(
        atPath: directory, withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700])
      chmod(directory, 0o700)
      try AgentSocket.checkDirectory(path)

      let fd = socket(AF_UNIX, SOCK_STREAM, 0)
      if fd < 0 {
        throw AgentError.internal("socket failed")
      }
      var address = try AgentSocket.address(path)
      unlink(path)
      if AgentSocket.withSockaddr(&address, { bind(fd, $0, $1) }) != 0 {
        throw AgentError.internal("cannot bind \(path): \(String(cString: strerror(errno)))")
      }
      chmod(path, 0o600)
      if listen(fd, 16) != 0 {
        throw AgentError.internal("listen failed: \(String(cString: strerror(errno)))")
      }
      let thread = Thread { [self] in
        while true {
          let client = accept(fd, nil, nil)
          if client < 0 {
            continue
          }
          serve(client)
          close(client)
        }
      }
      thread.start()
    }

    func stop() {
      unlink(path)
    }

    private func serve(_ fd: Int32) {
      var uid: uid_t = 0
      var gid: gid_t = 0
      if getpeereid(fd, &uid, &gid) != 0 || uid != getuid() {
        return
      }
      AgentSocket.setTimeout(fd, seconds: 5)
      let response: AgentResponse
      do {
        let request = try JSONDecoder().decode(AgentRequest.self, from: AgentSocket.readLine(fd))
        response = state.handle(request)
      } catch {
        response = AgentResponse(error: .invalid(error.localizedDescription))
      }
      if let data = try? JSONEncoder().encode(response) {
        try? AgentSocket.writeAll(fd, data + Data([0x0a]))
      }
    }
  }
#endif
