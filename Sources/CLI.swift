import Foundation

let version = "v0.2.1"

@main
struct CLI {
  static func main() {
    do {
      let plugin = Plugin(crypto: CryptoKitCrypto(), stream: StandardIOStream())
      let options = try Options.parse(CommandLine.arguments)
      switch options.command {
      case .help:
        print(Options.help)
      case .version:
        print(version)
      case .keygen:
        var applicationPassword: Data? = nil
        if options.accessControl == .applicationPassword {
          #if os(macOS)
            applicationPassword = try PasswordPrompt.readNew(
              description: "Enter a password to protect the new key")
          #else
            throw Plugin.Error.seUnsupported
          #endif
        }
        let result = try plugin.generateKey(
          accessControl: options.accessControl.keyAccessControl,
          recipientType: options.recipientType.recipientType, now: Date(),
          pq: options.pq, applicationPassword: applicationPassword)
        if let outputFile = options.output {
          FileManager.default.createFile(
            atPath: outputFile,
            contents: Data(result.0.utf8),
            attributes: [.posixPermissions: 0o600]
          )
          print("Public key: \(result.1)")
        } else {
          print(result.0)
        }
      case .recipients:
        var input = ""
        if let inputFile = options.input {
          input = try String(contentsOfFile: inputFile, encoding: .utf8)
        } else {
          input = try String(data: FileHandle.standardInput.readToEnd()!, encoding: .utf8)!
        }
        let result = try plugin.generateRecipients(
          input: input, recipientType: options.recipientType.recipientType, pq: options.pq)
        if let outputFile = options.output {
          FileManager.default.createFile(
            atPath: outputFile,
            contents: Data(result.utf8),
            attributes: [.posixPermissions: 0o600]
          )
        } else if result != "" {
          print(result)
        }
      case .plugin(let sm):
        switch sm {
        case .recipientV1:
          plugin.runRecipientV1()
        case .identityV1:
          #if os(macOS)
            plugin.agent = UnixSocketAgentClient.available()
          #endif
          plugin.runIdentityV1()
        }
      case .agent, .unlock, .lock, .status:
        #if os(macOS)
          try AgentCLI.run(options, crypto: plugin.crypto)
        #else
          throw Plugin.Error.seUnsupported
        #endif
      }
    } catch {
      print("\(CommandLine.arguments[0]): error: \(error.localizedDescription)")
      exit(-1)
    }
  }
}

/// Command-line options parser
struct Options {
  enum Error: LocalizedError, Equatable {
    case unknownOption(String)
    case missingValue(String)
    case invalidValue(String, String)

    public var errorDescription: String? {
      switch self {
      case .unknownOption(let option): return "unknown option: `\(option)`"
      case .missingValue(let option): return "missing value for option `\(option)`"
      case .invalidValue(let option, let value):
        return "invalid value for option `\(option)`: `\(value)`"
      }
    }
  }

  enum StateMachine: String {
    case recipientV1 = "recipient-v1"
    case identityV1 = "identity-v1"
  }

  enum Command: Equatable {
    case help
    case version
    case keygen
    case recipients
    case plugin(StateMachine)
    case agent
    case unlock
    case lock
    case status
  }
  var command: Command

  var output: String?
  var input: String?

  var pq: Bool = false

  var socket: String?
  var timeout: TimeInterval?
  var lockOnSleep = false
  var lockOnScreenLock = false

  enum AccessControl: String {
    case none = "none"
    case passcode = "passcode"
    case anyBiometry = "any-biometry"
    case anyBiometryOrPasscode = "any-biometry-or-passcode"
    case anyBiometryAndPasscode = "any-biometry-and-passcode"
    case currentBiometry = "current-biometry"
    case currentBiometryAndPasscode = "current-biometry-and-passcode"
    case applicationPassword = "application-password"

    var keyAccessControl: KeyAccessControl {
      switch self {
      case .none: return KeyAccessControl.none
      case .passcode: return KeyAccessControl.passcode
      case .anyBiometry: return KeyAccessControl.anyBiometry
      case .anyBiometryOrPasscode: return KeyAccessControl.anyBiometryOrPasscode
      case .anyBiometryAndPasscode: return KeyAccessControl.anyBiometryAndPasscode
      case .currentBiometry: return KeyAccessControl.currentBiometry
      case .currentBiometryAndPasscode: return KeyAccessControl.currentBiometryAndPasscode
      case .applicationPassword: return KeyAccessControl.applicationPassword
      }
    }
  }
  var accessControl = AccessControl.anyBiometryOrPasscode

  enum RecipientType: String {
    case se = "se"
    case tag = "tag"

    var recipientType: age_plugin_se.RecipientType {
      switch self {
      case .se: return .se
      case .tag: return .tag
      }
    }
  }

  var recipientType: RecipientType = .se

  static let help =
    """
    Usage:
      age-plugin-se keygen [--pq] [-o OUTPUT] [--access-control ACCESS_CONTROL] [--recipient-type RECIPIENT_TYPE]
      age-plugin-se recipients [--pq] [-o OUTPUT] [-i INPUT] [--recipient-type RECIPIENT_TYPE]
      age-plugin-se agent [--socket SOCKET] [--timeout SECONDS] [--lock-on-sleep] [--lock-on-screen-lock]
      age-plugin-se unlock [--socket SOCKET] [-i INPUT]
      age-plugin-se lock [--socket SOCKET]
      age-plugin-se status [--socket SOCKET]

    Description:
      The `keygen` subcommand generates a new private key bound to the current 
      Secure Enclave, with the given access controls, and outputs it to OUTPUT 
      or standard output.

      The `recipients` subcommand reads an identity file from INPUT or standard 
      input, and outputs the corresponding recipient(s) to OUTPUT or to standard 
      output.

      The `agent` subcommand runs an agent that keeps keys protected by an
      application password unlocked, so that the password only needs to be
      entered once (e.g. once per login). The plug-in uses the agent when it is
      running, and unlocks keys in the agent on first use. Keys stay unlocked
      until `lock`, until TIMEOUT seconds have passed, or until the agent stops.

      The `unlock` subcommand unlocks the application password keys of the
      identity file INPUT (or standard input) in the agent, asking for the
      password on the terminal, or using pinentry (PINENTRY_PROGRAM, default
      pinentry-mac) if there is no terminal.

      The `lock` subcommand locks all keys in the agent. The `status`
      subcommand shows how many keys are unlocked.

    Options:
      --access-control ACCESS_CONTROL   Access control for using the generated key.
                                        
                                        When using current biometry, adding or removing a 
                                        fingerprint stops the key from working. Removing an 
                                        added fingerprint enables the key again. 

                                        `application-password` protects the key with a
                                        password of your choice, which is checked by the
                                        Secure Enclave. Use the agent to enter it only
                                        once. Not supported for post-quantum keys.

                                        Supported values: none, passcode, 
                                          any-biometry, any-biometry-and-passcode, 
                                          any-biometry-or-passcode, current-biometry, 
                                          current-biometry-and-passcode,
                                          application-password
                                        Default: any-biometry-or-passcode.                          

      -i, --input INPUT                 Read data from the file at path INPUT

      -o, --output OUTPUT               Write the result to the file at path OUTPUT

      --pq                              Generate post-quantum keys

      --socket SOCKET                   Agent socket path. Default: $AGE_PLUGIN_SE_AGENT_SOCK, or
                                        ~/Library/Application Support/age-plugin-se/agent.sock

      --timeout SECONDS                 Lock keys this many seconds after unlocking them

      --lock-on-sleep                   Lock keys when the system goes to sleep

      --lock-on-screen-lock             Lock keys when the screen is locked

      --recipient-type RECIPIENT_TYPE   Recipient type to generate.

                                        `tag` recipients use built-in support in
                                        age (>=v1.3.0), and don't require this plug-in to
                                        be installed to encrypt.

                                        Post-quantum keys (generated with `--pq`) always
                                        use the `tag` recipient type.

                                        Supported values: se, tag.
                                        Default: se.
                                        The default will change to `tag` in future versions.

    Example:
      $ age-plugin-se keygen -o key.txt
      Public key: age1se1qg8vwwqhztnh3vpt2nf2xwn7famktxlmp0nmkfltp8lkvzp8nafkqleh258
      $ tar cvz ~/data | age -r age1se1qgg72x2qfk9wg3wh0qg9u0v7l5dkq4jx69fv80p6wdus3ftg6flwg5dz2dp > data.tar.gz.age
      $ age --decrypt -i key.txt data.tar.gz.age > data.tar.gz
    """

  static func parse(_ args: [String]) throws -> Options {
    var opts = Options(command: .help)
    var i = 1
    while i < args.count {
      let arg = args[i]
      if arg == "keygen" {
        opts.command = .keygen
      } else if arg == "recipients" {
        opts.command = .recipients
      } else if arg == "agent" {
        opts.command = .agent
      } else if arg == "unlock" {
        opts.command = .unlock
      } else if arg == "lock" {
        opts.command = .lock
      } else if arg == "status" {
        opts.command = .status
      } else if arg == "--lock-on-sleep" {
        opts.lockOnSleep = true
      } else if arg == "--lock-on-screen-lock" {
        opts.lockOnScreenLock = true
      } else if ["--help", "-h"].contains(arg) {
        opts.command = .help
        break
      } else if ["--version"].contains(arg) {
        opts.command = .version
        break
      } else if ["--pq"].contains(arg) {
        opts.pq = true
      } else if [
        "--age-plugin", "-i", "--input", "-o", "--output", "--access-control", "--recipient-type",
        "--socket", "--timeout",
      ].contains(where: {
        arg == $0 || arg.hasPrefix($0 + "=")
      }) {
        let argps = arg.split(separator: "=", maxSplits: 1)
        let value: String
        if argps.count == 1 {
          i += 1
          if i >= args.count {
            throw Error.missingValue(arg)
          }
          value = args[i]
        } else {
          value = String(argps[1])
        }
        let arg = String(argps[0])
        switch arg {
        case "--age-plugin":
          opts.command = try .plugin(
            StateMachine(rawValue: value) ?? { throw Error.invalidValue(arg, value) }())
        case "-i", "--input":
          opts.input = value
        case "-o", "--output":
          opts.output = value
        case "--access-control":
          opts.accessControl =
            try AccessControl(rawValue: value) ?? { throw Error.invalidValue(arg, value) }()
        case "--recipient-type":
          opts.recipientType =
            try RecipientType(rawValue: value) ?? { throw Error.invalidValue(arg, value) }()
        case "--socket":
          opts.socket = value
        case "--timeout":
          guard let timeout = TimeInterval(value), timeout > 0 else {
            throw Error.invalidValue(arg, value)
          }
          opts.timeout = timeout
        default:
          assert(false)
        }
      } else {
        throw Error.unknownOption(arg)
      }
      i += 1
    }
    return opts
  }
}
