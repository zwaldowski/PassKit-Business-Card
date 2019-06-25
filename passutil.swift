#!/usr/bin/env xcrun swift -swift-version 5

import Foundation
import Security
import CommonCrypto

// MARK: - Extensions

func bail(_ text: String) -> Never {
    struct Stderr: TextOutputStream {
        let fd = Darwin.stderr

        func write(_ string: String) {
            flockfile(fd)
            for c in string.utf8 {
                putc_unlocked(numericCast(c), fd)
            }
            funlockfile(fd)
        }
    }

    var stderr = Stderr()
    print(text, to: &stderr)
    exit(-1)
}

extension Collection where Element: Equatable {

    func value(after flag: Element) -> Element? {
        return firstIndex(of: flag).map(suffix)?.dropFirst().first
    }


    @available(*, deprecated)
    func value<T>(after flag: Iterator.Element, map transform: (Iterator.Element) -> T?) -> T? {
        return value(after: flag).flatMap(transform)
    }

}


extension String {

    init<Data: Collection>(hexEncoding bytes: Data) where Data.Element == UInt8 {
        self.init()
        reserveCapacity(bytes.count * 2)
        for byte in bytes {
            if byte < 16 { append("0") }
            append(String(byte, radix: 16, uppercase: false ))
        }
    }

}

extension Data {

    func SHA1Sum() -> String {
        let data = withUnsafeBytes { (buffer) -> [UInt8] in
            var array = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
            CC_SHA1(buffer.baseAddress, CC_LONG(buffer.count), &array)
            return array
        }

        return String(hexEncoding: data)
    }

}

private extension SecCertificate {

    var commonName: String {
        var commonName: CFString?
        SecCertificateCopyCommonName(self, &commonName)
        return (commonName as String?) ?? ""
    }

}

// MARK: - Utilities

func passTypeIdentifier(passAt url: URL) -> String? {
    let contentsURL = url.appendingPathComponent("pass").appendingPathExtension("json")
    guard let contentsData = try? Data(contentsOf: contentsURL),
        let contentsDictionary = (try? JSONSerialization.jsonObject(with: contentsData)) as? [String: Any],
        let identifier = contentsDictionary["passTypeIdentifier"] as? String else { return nil }
    return identifier
}

func passSigningIdentity(suffix: String) -> SecIdentity? {
    let matchQuery = [
        kSecClass as String: kSecClassIdentity as String,
        kSecMatchSubjectEndsWith as String: suffix,
        kSecReturnRef as String: true
    ] as [AnyHashable: Any]

    var result: CFTypeRef?
    guard SecItemCopyMatching(matchQuery as CFDictionary, &result) == 0 else { return nil }
    return (result as! SecIdentity)
}

// MARK: -

enum Command {
    case help
    case sign(URL, output: URL?, suffix: String?)
    case verify(URL)

    init(arguments: [String] = CommandLine.arguments) {
        let arguments = arguments.dropFirst()
        if arguments.first == "sign", let input = arguments.dropFirst().value(after: "-i").flatMap(URL.init(fileURLWithPath:)) {
            let output = arguments.dropFirst().value(after: "-o").flatMap(URL.init(fileURLWithPath:))
            let certSuffix = arguments.dropFirst().value(after: "-c")
            self = .sign(input, output: output, suffix: certSuffix)
        } else if arguments.first == "verify", let input = arguments.dropFirst().value(after: "-i").flatMap(URL.init(fileURLWithPath:)) {
            self = .verify(input)
        } else {
            self = .help
        }
    }
}

// MARK: -

struct PassManifests {



}

let command = Command()

let fileManager = FileManager()
let temporaryDirectory = fileManager.temporaryDirectory.appendingPathComponent(UUID().uuidString)

switch command {
case .help:
    print("""
    usage:
        passutil sign -i <raw pass> [-o <path>] [-c <certSuffix>]
            Sign and zip a raw pass directory
        passutil verify -i <pass>
            Unzip and verify a signed pass's signature and manifest. This DOES NOT validate pass content.
        passutil help
            Shows this help.
    """)
case let .sign(input, output, certSuffix):
    // Dictionary to store our manifest hashes
    var manifests = [String: String]()

    // Make sure we're starting fresh
    _ = try? fileManager.removeItem(at: temporaryDirectory)

    // Copy the pass to the temporary spot
    try fileManager.copyItem(at: input, to: temporaryDirectory)

    // For each file in the pass directory...
    let keys: Set<URLResourceKey> = [ .isRegularFileKey, .isHiddenKey ]
    for url in try fileManager.contentsOfDirectory(at: temporaryDirectory, includingPropertiesForKeys: Array(keys)) {
        let resources = try url.resourceValues(forKeys: keys)
        if resources.isRegularFile == true, resources.isHidden == false {
            manifests[url.lastPathComponent] = try Data(contentsOf: url).SHA1Sum()
        } else {
            try fileManager.removeItem(at: url)
        }
    }

    // Write out the manifest dictionary
    let manifestURL = temporaryDirectory.appendingPathComponent("manifest").appendingPathExtension("json")
    let manifestData = try JSONEncoder().encode(manifests)
    try manifestData.write(to: manifestURL)

    guard let certSuffix = certSuffix ?? passTypeIdentifier(passAt: input) else {
        bail("Couldn't find a passTypeIdentifier in the pass")
    }

    guard let identifier = passSigningIdentity(suffix: certSuffix) else {
        bail("Couldn't find an identity for \(certSuffix)")
    }

    var resultCfData: CFData?

    let status = manifestData.withUnsafeBytes { (buffer) in
        CMSEncodeContent(identifier, nil, nil, true, .attrSigningTime, buffer.baseAddress!, buffer.count, &resultCfData)
    }

    guard status == 0, let resultData = resultCfData as Data? else {
        bail("Could not sign manifest data: \((SecCopyErrorMessageString(status, nil) as String?) ?? "unknown error")")
    }

    // Write signature to disk
    try resultData.write(to: temporaryDirectory.appendingPathComponent("signature"))

    // Create ".pkpass" output url
    let output = (output?.deletingPathExtension() ?? input.deletingLastPathComponent().appendingPathComponent(input.deletingPathExtension().lastPathComponent)).appendingPathExtension("pkpass")

    _ = try? fileManager.removeItem(at: output)

    let zipTask = Process()
    zipTask.launchPath = "/usr/bin/zip"
    zipTask.currentDirectoryPath = temporaryDirectory.path
    zipTask.arguments = [ "-q", "-r", output.path, "." ]
    zipTask.launch()
    zipTask.waitUntilExit()

    guard zipTask.terminationStatus == 0 else {
        bail("Could not compress pass")
    }

    print("Finished! Written to \(output.path)")
case let .verify(input):
    // unzip the pass to a temporary place
    let zipTask = Process()
    zipTask.launchPath = "/usr/bin/unzip"
    zipTask.arguments = [ "-q", "-o", input.path, "-d", temporaryDirectory.path ]
    zipTask.launch()
    zipTask.waitUntilExit()

    guard zipTask.terminationStatus == 0 else {
        bail("Could not extract pass")
    }

    // Validate manifest
    let manifestURL = temporaryDirectory.appendingPathComponent("manifest").appendingPathExtension("json")
    let manifestData = try Data(contentsOf: manifestURL)

    var manifest = try JSONSerialization.jsonObject(with: manifestData) as? [String: String] ?? [:]

    let keys: Set<URLResourceKey> = [ .fileSizeKey, .isSymbolicLinkKey ]
    for url in try fileManager.contentsOfDirectory(at: temporaryDirectory, includingPropertiesForKeys: Array(keys)) {
        let resources = try url.resourceValues(forKeys: keys)

        guard resources.isSymbolicLink != true else {
            bail("Pass contains a symlink, \(url.path), which is illegal")
        }

        guard url.lastPathComponent != "manifest.json", url.lastPathComponent != "signature" else {
            continue
        }

        guard let manifestSHA1 = manifest.removeValue(forKey: url.lastPathComponent) else {
            bail("No entry in manifest for \(url.path)")
        }

        let currentSHA1 = try Data(contentsOf: url).SHA1Sum()

        if currentSHA1 != manifestSHA1 {
            bail("For \(url.lastPathComponent), manifest's listed SHA1 hash \(manifestSHA1) doesn't match computed hash, \(currentSHA1)")
        }
    }

    guard manifest.isEmpty else {
        bail("Manifest had extra entries: \(Array(manifest.keys))")
    }

    // Validate signature
    let signatureURL = temporaryDirectory.appendingPathComponent("signature")
    let signatureData = try Data(contentsOf: signatureURL)

    // set up a cms decoder
    var decoder: CMSDecoder!
    CMSDecoderCreate(&decoder)
    CMSDecoderSetDetachedContent(decoder, manifestData as CFData)
    _ = signatureData.withUnsafeBytes { (buffer) in
        CMSDecoderUpdateMessage(decoder, buffer.baseAddress!, buffer.count)
    }
    CMSDecoderFinalizeMessage(decoder)

    let policy = SecPolicyCreateBasicX509()
    var status = CMSSignerStatus.unsigned
    var outTrust: SecTrust?
    var result: OSStatus = noErr

    // obtain the status
    CMSDecoderCopySignerStatus(decoder!, 0, policy, false, &status, &outTrust, &result)

    guard case .valid = status, let trust = outTrust else {
        bail("Error validating signature: \((SecCopyErrorMessageString(result, nil) as String?) ?? "unknown error")")
    }

    print("Signature validated!")

    // Validate certificate trust chain
    var trustResult = SecTrustResultType.unspecified
    SecTrustEvaluate(trust, &trustResult)

    guard case .unspecified = trustResult else {
        let allProperties = (SecTrustCopyProperties(trust) as? [[String: Any]]) ?? []
        let propertyStrings = allProperties.lazy.compactMap({ (properties) -> String? in
            guard let title = properties[kSecPropertyTypeTitle as String] as? String else { return nil }
            let error = properties[kSecPropertyTypeError as String] as? String
            return "\t\(title): \(error ?? "(nil)")"
        }).joined(separator: "\n")
        bail("Error validating trust chain:\n\(propertyStrings)")
    }

    var cfCertificates: CFArray?
    CMSDecoderCopyAllCerts(decoder!, &cfCertificates)
    let certificates = (cfCertificates as? [SecCertificate]) ?? []

    guard certificates.contains(where: {
        $0.commonName == "Apple Worldwide Developer Relations Certification Authority"
    }) else {
        bail("The Apple WWDR Intermediate Certificate must be included in the signature.\n\t<https://developer.apple.com/certificationauthority/AppleWWDRCA.cer>")
    }

    print("Validated trust chain: (")
    for (i, certificate) in certificates.enumerated() {
        print("\t\(i): \(certificate.commonName)")
    }
    print(")")
}
