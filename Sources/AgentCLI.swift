#if os(macOS)
  import AppKit
  import Foundation

  /// `agent`, `unlock`, `lock`, and `status` subcommands
  enum AgentCLI {
    enum Error: LocalizedError {
      case agentNotRunning(String)
      case noPasswordKeys

      public var errorDescription: String? {
        switch self {
        case .agentNotRunning(let path): return "agent not running at \(path)"
        case .noPasswordKeys: return "no keys protected by an application password found"
        }
      }
    }

    static func run(_ options: Options, crypto: Crypto) throws {
      let path = options.socket ?? AgentSocket.defaultPath
      switch options.command {
      case .agent:
        try runAgent(path: path, options: options)
      case .unlock:
        try unlock(path: path, input: options.input, crypto: crypto)
      case .lock:
        try client(path).lock()
      case .status:
        let unlocked = try client(path).status()
        print("\(unlocked) key\(unlocked == 1 ? "" : "s") unlocked")
      default:
        assert(false)
      }
    }

    static func client(_ path: String) throws -> UnixSocketAgentClient {
      let client = UnixSocketAgentClient(path: path)
      do {
        _ = try client.status()
      } catch {
        throw Error.agentNotRunning(path)
      }
      return client
    }

    static func runAgent(path: String, options: Options) throws {
      let state = AgentState(keyStore: SecureEnclaveKeyStore(), timeout: options.timeout)
      let server = AgentServer(path: path, state: state)
      try server.start()

      var observers: [NSObjectProtocol] = []
      if options.lockOnSleep {
        observers.append(
          NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.willSleepNotification, object: nil, queue: nil
          ) { _ in state.lockAll() })
      }
      if options.lockOnScreenLock {
        observers.append(
          DistributedNotificationCenter.default().addObserver(
            forName: Notification.Name("com.apple.screenIsLocked"), object: nil, queue: nil
          ) { _ in state.lockAll() })
      }
      if options.timeout != nil {
        // Drop expired authorizations even when no requests come in
        Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { _ in
          _ = state.handle(AgentRequest(op: "status"))
        }
      }

      var signalSources: [DispatchSourceSignal] = []
      for sig in [SIGINT, SIGTERM, SIGHUP] {
        signal(sig, SIG_IGN)
        let source = DispatchSource.makeSignalSource(signal: sig, queue: .main)
        source.setEventHandler {
          state.lockAll()
          server.stop()
          exit(0)
        }
        source.resume()
        signalSources.append(source)
      }

      FileHandle.standardError.write(Data("age-plugin-se agent listening on \(path)\n".utf8))
      withExtendedLifetime((observers, signalSources)) {
        RunLoop.main.run()
      }
    }

    static func unlock(path: String, input: String?, crypto: Crypto) throws {
      let client = try client(path)
      let contents: String
      if let input = input {
        contents = try String(contentsOfFile: input, encoding: .utf8)
      } else {
        contents = String(decoding: FileHandle.standardInput.readDataToEndOfFile(), as: UTF8.self)
      }
      var found = false
      for line in contents.split(whereSeparator: \.isNewline) {
        let line = line.trimmingCharacters(in: .whitespaces)
        if line.isEmpty || line.hasPrefix("#") || !line.hasPrefix("AGE-PLUGIN-SE-") {
          continue
        }
        let identity = try Identity(ageIdentity: line, crypto: crypto)
        if !identity.requiresApplicationPassword {
          continue
        }
        found = true
        let key = identity.p256PrivateKey.dataRepresentation
        let recipient = identity.recipient.ageRecipient(type: .tag)
        var unlocked = false
        for attempt in 1...ApplicationPasswordUnlocker.maxAttempts {
          let password = try PasswordPrompt.read(
            description: attempt == 1
              ? "Enter the password for \(recipient)"
              : "Incorrect password. Enter the password for \(recipient)")
          do {
            try client.unlock(key: key, password: password)
            unlocked = true
            break
          } catch AgentError.badPassword {
            continue
          }
        }
        if !unlocked {
          throw Plugin.Error.incorrectApplicationPassword
        }
        FileHandle.standardError.write(Data("Unlocked \(recipient)\n".utf8))
      }
      if !found {
        throw Error.noPasswordKeys
      }
    }
  }
#endif
