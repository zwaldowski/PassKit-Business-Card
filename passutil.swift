#!/usr/bin/env xcrun swift

import Foundation
import Security

// MARK: - Extensions

func bail(_ text: String) -> Never {
    struct Stream: TextOutputStream {
        let fd: UnsafeMutablePointer<FILE>

        func write(_ string: String) {
            flockfile(fd)
            for c in string.utf8 {
                putc_unlocked(numericCast(c), fd)
            }
            funlockfile(fd)
        }
    }

    var stderr = Stream(fd: Darwin.stderr)
    print(text, to: &stderr)
    exit(-1)
}

extension Collection where Iterator.Element: Equatable {

    func value<T>(after flag: Iterator.Element, map transform: (Iterator.Element) -> T?) -> T? {
        return index(of: flag).flatMap({ index($0, offsetBy: 1, limitedBy: endIndex) }).map({ self[$0] }).flatMap(transform)
    }

}

extension Data {

    private typealias calculateSHA1_fn = @convention(c) (UnsafeRawPointer, Int32, UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8>
    private static let calculateSHA1 = unsafeBitCast(dlsym(UnsafeMutableRawPointer(bitPattern: -2), "CC_SHA1"), to: calculateSHA1_fn.self)

    func SHA1Sum() -> String {
        let data = withUnsafeBytes { (srcPtr: UnsafePointer<UInt8>) -> Data in
            var data = Data(count: 20)
            _ = data.withUnsafeMutableBytes { (destPtr) in
                Data.calculateSHA1(UnsafeRawPointer(srcPtr), numericCast(count), destPtr)
            }
            return data
        }

        var string = ""
        for byte in data {
            if byte <= 0xF { string.unicodeScalars.append("0") }
            string += String(byte, radix: 16)
        }
        return string
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

    init(arguments: [String]) {
        let arguments = arguments.dropFirst()
        if arguments.first == "sign", let input = arguments.dropFirst().value(after: "-i", map: URL.init(fileURLWithPath:)) {
            let output = arguments.dropFirst().value(after: "-o", map: URL.init(fileURLWithPath:))
            let certSuffix = arguments.dropFirst().value(after: "-c", map: { $0 })
            self = .sign(input, output: output, suffix: certSuffix)
        } else if arguments.first == "verify", let input = arguments.dropFirst().value(after: "-i", map: URL.init(fileURLWithPath:)) {
            self = .verify(input)
        } else {
            self = .help
        }
    }
}

// MARK: -

let command = Command(arguments: CommandLine.arguments)

let fileManager = FileManager()
let temporaryDirectory = fileManager.temporaryDirectory.appendingPathComponent(UUID().uuidString)

switch command {
case .help:
    print("usage:\n\tsignpass sign -i <raw pass> [-o <path>] [-c <certSuffix>]")
    print("\t\tSign and zip a raw pass directory\n")
    print("\tsignpass verify -i <pass>")
    print("\t\tUnzip and verify a signed pass's signature and manifest. This DOES NOT validate pass content.\n")
    print("\tsignpass help")
    print("\t\tShows this help.\n")
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
    let manifestData = try JSONSerialization.data(withJSONObject: manifests)
    try manifestData.write(to: manifestURL)

    guard let certSuffix = certSuffix ?? passTypeIdentifier(passAt: input) else {
        bail("Couldn't find a passTypeIdentifier in the pass")
    }

    guard let identifier = passSigningIdentity(suffix: certSuffix) else {
        bail("Couldn't find an identity for \(certSuffix)")
    }

    var resultCfData: CFData?

    let status = manifestData.withUnsafeBytes { (ptr: UnsafePointer<UInt8>) in
        CMSEncodeContent(identifier, nil, nil, true, .attrSigningTime, UnsafeRawPointer(ptr), manifestData.count, &resultCfData)
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
    var decoder: CMSDecoder?
    CMSDecoderCreate(&decoder)
    CMSDecoderSetDetachedContent(decoder!, manifestData as CFData)
    _ = signatureData.withUnsafeBytes { (ptr: UnsafePointer<UInt8>) in
        CMSDecoderUpdateMessage(decoder!, ptr, signatureData.count)
    }
    CMSDecoderFinalizeMessage(decoder!)

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
        let propertyStrings = allProperties.lazy.flatMap({ (properties) -> String? in
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
