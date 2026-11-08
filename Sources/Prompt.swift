import Foundation

#if os(macOS)
  /// Asks for a password on the terminal, or using pinentry if there is no terminal
  enum PasswordPrompt {
    enum Error: LocalizedError {
      case cancelled
      case pinentry(String)
      case mismatch
      case empty

      public var errorDescription: String? {
        switch self {
        case .cancelled: return "password entry cancelled"
        case .pinentry(let message): return "pinentry: \(message)"
        case .mismatch: return "passwords didn't match"
        case .empty: return "password cannot be empty"
        }
      }
    }

    static func read(description: String, prompt: String = "Password:") throws -> Data {
      var buffer = [CChar](repeating: 0, count: 1024)
      defer {
        buffer.withUnsafeMutableBytes { _ = memset_s($0.baseAddress, $0.count, 0, $0.count) }
      }
      FileHandle.standardError.write(Data("\(description)\n".utf8))
      if readpassphrase("\(prompt) ", &buffer, buffer.count, RPP_REQUIRE_TTY) != nil {
        return Data(buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) })
      }
      return try pinentry(description: description, prompt: prompt)
    }

    static func readNew(description: String) throws -> Data {
      let password = try read(description: description)
      if password.isEmpty {
        throw Error.empty
      }
      if try read(description: "Confirm the password", prompt: "Confirm:") != password {
        throw Error.mismatch
      }
      return password
    }

    static var pinentryProgram: String {
      if let program = ProcessInfo.processInfo.environment["PINENTRY_PROGRAM"], !program.isEmpty {
        return program
      }
      return "pinentry-mac"
    }

    /// Minimal Assuan client for pinentry
    static func pinentry(description: String, prompt: String) throws -> Data {
      let process = Process()
      process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
      process.arguments = [pinentryProgram]
      let input = Pipe()
      let output = Pipe()
      process.standardInput = input
      process.standardOutput = output
      do {
        try process.run()
      } catch {
        throw Error.pinentry("cannot start \(pinentryProgram): \(error.localizedDescription)")
      }
      defer {
        try? input.fileHandleForWriting.close()
        process.waitUntilExit()
      }
      guard let reader = fdopen(output.fileHandleForReading.fileDescriptor, "r") else {
        throw Error.pinentry("cannot read from pinentry")
      }
      defer { fclose(reader) }

      func readResponse() throws -> Data? {
        var data: Data? = nil
        while true {
          var line: UnsafeMutablePointer<CChar>? = nil
          var capacity = 0
          defer { free(line) }
          if getline(&line, &capacity, reader) < 0 {
            throw Error.pinentry("unexpected end of output")
          }
          let text = String(cString: line!).trimmingCharacters(in: .newlines)
          if text.hasPrefix("OK") {
            return data
          } else if text.hasPrefix("ERR") {
            if text.contains("cancel") || text.contains("Cancel") {
              throw Error.cancelled
            }
            throw Error.pinentry(text)
          } else if text.hasPrefix("D ") {
            data = (data ?? Data()) + percentDecode(String(text.dropFirst(2)))
          }
        }
      }
      func send(_ command: String) throws -> Data? {
        input.fileHandleForWriting.write(Data("\(command)\n".utf8))
        return try readResponse()
      }

      _ = try readResponse()
      _ = try send("SETTITLE age-plugin-se")
      _ = try send("SETDESC \(percentEncode(description))")
      _ = try send("SETPROMPT \(percentEncode(prompt))")
      let pin = try send("GETPIN") ?? Data()
      _ = try? send("BYE")
      return pin
    }

    static func percentEncode(_ s: String) -> String {
      return s.replacingOccurrences(of: "%", with: "%25")
        .replacingOccurrences(of: "\r", with: "%0D")
        .replacingOccurrences(of: "\n", with: "%0A")
    }

    static func percentDecode(_ s: String) -> Data {
      var result = Data()
      var bytes = Array(s.utf8)[...]
      while let byte = bytes.popFirst() {
        if byte == UInt8(ascii: "%"), bytes.count >= 2,
          let value = UInt8(String(decoding: bytes.prefix(2), as: UTF8.self), radix: 16)
        {
          result.append(value)
          bytes = bytes.dropFirst(2)
        } else {
          result.append(byte)
        }
      }
      return result
    }
  }
#endif
