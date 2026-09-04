//
//  Macho.swift
//  PlayCover
//

import Foundation

class Macho {
    static func stripBinary(_ binary: inout Data) throws {
        var header = binary.extract(fat_header.self)
        var offset = MemoryLayout.size(ofValue: header)
        let shouldSwap = header.magic == FAT_CIGAM

        if header.magic == FAT_MAGIC || header.magic == FAT_CIGAM {
            // Make sure the endianness is correct
            if shouldSwap {
                swap_fat_header(&header, NXHostByteOrder())
            }

            for _ in 0..<header.nfat_arch {
                var arch = binary.extract(fat_arch.self, offset: offset)
                if shouldSwap {
                    swap_fat_arch(&arch, 1, NXHostByteOrder())
                }

                if arch.cputype == CPU_TYPE_ARM64 {
                    print("Found ARM64 arch in fat binary")

                    binary = binary
                        .subdata(in: Int(arch.offset)..<Int(arch.offset+arch.size))

                    return
                }

                offset += Int(MemoryLayout.size(ofValue: arch))
            }

            throw PlayCoverError.failedToStripBinary
        }
    }

    static func convertMacho(_ macho: URL) throws {
        print("Converting MachO at \(macho.path)")

        var binary = try Data(contentsOf: macho)

        print("Stripping MachO...")
        try stripBinary(&binary)
        print("Removing version commands...")
        try replaceAllVersionCommands(&binary)
        print("Replacing instances of @rpath dylibs...")
        try replaceLibraries(&binary)

        print("Writing revised MachO...")
        try FileManager.default.removeItem(at: macho)
        try binary.write(to: macho)
    }

    static func replaceLibraries(_ binary: inout Data) throws {
        let dylibsToReplace = ["libswiftUIKit"]

        for dylib in dylibsToReplace {
            let rpathDylib = "@rpath/\(dylib).dylib"
            let libDylib = "/System/iOSSupport/usr/lib/swift/\(dylib).dylib"

            // 1. Check if dylib LC exists
            // 2. If it exists, take notes of its command type and dylib struct
            // 3. Replace existing LC with new dylib path

            try replaceLibrary(&binary, rpathDylib, libDylib)
        }
    }

    static func replaceLibrary(_ binary: inout Data, _ rpath: String, _ lib: String) throws {
        var dylibCommandType: UInt32 = 0
        var oldDylib: dylib?

        try replaceLastCommand(&binary, satisfy: {commandData, shouldSwap in
            // Perform steps 1-2
            let loadCommand = commandData.extract(load_command.self,
                                                  offset: commandData.startIndex,
                                                  swap: shouldSwap ? swap_load_command:nil)
            if ![LC_LOAD_WEAK_DYLIB, UInt32(LC_LOAD_DYLIB)].contains(loadCommand.cmd) {
                return false
            }
            let dylibCommand = commandData.extract(dylib_command.self,
                                                   offset: commandData.startIndex,
                                                   swap: shouldSwap ? swap_dylib_command:nil)
            if String(data: commandData,
                      offset: commandData.startIndex,
                      commandSize: Int(dylibCommand.cmdsize),
                      loadCommandString: dylibCommand.dylib.name) != rpath {
                return false
            }
            dylibCommandType = dylibCommand.cmd
            oldDylib = dylibCommand.dylib
            return true

        }, with: {shouldSwap in
            guard var newDylib = oldDylib else {
                // dylib with given rpath was not found in binary
                return nil
            }

            print("Found \(rpath) in binary")

            // Perform step 3
            let dylibCommandFixedSize = MemoryLayout<dylib_command>.size
            let stringLength = lib.lengthOfBytes(using: String.Encoding.utf8)
            // Align to 8 bytes, leave at least 1 zero for C-style string ending
            let padding = 8 - (stringLength % 8)
            let newDylibCommandSize = dylibCommandFixedSize + stringLength + padding

            newDylib.name = lc_str(offset: UInt32(dylibCommandFixedSize))
            var command = dylib_command(cmd: dylibCommandType,
                                        cmdsize: UInt32(newDylibCommandSize),
                                        dylib: newDylib)
            guard let stringData = lib.data(using: String.Encoding.utf8) else {
                print("Failed to replace dylib command: unrecognized character in target path")
                return nil
            }
            if shouldSwap {
                swap_dylib_command(&command, NX_BigEndian)
            }
            var commandData = Data(bytes: &command, count: dylibCommandFixedSize)
            commandData.append(stringData)
            commandData.append(Data(count: padding))
            return commandData
        }, atEnd: false)
    }

    static func replaceAllVersionCommands(_ binary: inout Data) throws {
        let headerSize = MemoryLayout<mach_header_64>.size
        var header = binary.extract(mach_header_64.self)
        if header.magic != MH_MAGIC_64 && header.magic != MH_CIGAM_64 {
            print("Cannot replace version commands: Mach-O file is not 64-bit")
            throw PlayCoverError.appCorrupted
        }
        let shouldSwap = header.magic == MH_CIGAM_64
        if shouldSwap {
            swap_mach_header_64(&header, NXHostByteOrder())
        }

        let oldCommandsEnd = headerSize + Int(header.sizeofcmds)
        var keptCommands = Data()
        var removedTypes: [UInt32: Int] = [:]

        let walkedEnd = try iterateLoadCommands(binary: binary) { offset, needSwap in
            let loadCommand = binary.extract(load_command.self,
                                             offset: offset,
                                             swap: needSwap ? swap_load_command:nil)
            if isVersionCommand(loadCommand.cmd) {
                removedTypes[loadCommand.cmd, default: 0] += 1
            } else {
                keptCommands.append(binary[offset ..< offset + Int(loadCommand.cmdsize)])
            }
            return false
        }
        if walkedEnd != oldCommandsEnd {
            print("Error while replacing version commands: end of commands mismatch")
            if walkedEnd < oldCommandsEnd {
                // Preserve any unwalked bytes verbatim (corrupt ncmds safety net)
                keptCommands.append(binary[walkedEnd ..< oldCommandsEnd])
            }
        }

        let removedCount = removedTypes.values.reduce(0, +)
        if removedCount > Int(header.ncmds) {
            print("Cannot replace version commands: Mach-O file is corrupted")
            throw PlayCoverError.appCorrupted
        }
        let removedSummary = removedTypes.sorted { $0.key < $1.key }
            .map { "\(versionCommandName($0.key)): \($0.value)" }
            .joined(separator: ", ")
        print("Removed \(removedCount) version load command(s) (\(removedSummary))")

        var macCatalystCommand = build_version_command(cmd: UInt32(LC_BUILD_VERSION),
                                                       cmdsize: 24,
                                                       platform: UInt32(PLATFORM_MACCATALYST),
                                                       minos: 0x000b0000,
                                                       sdk: 0x000e0000,
                                                       ntools: 0)
        if shouldSwap {
            swap_build_version_command(&macCatalystCommand, NX_BigEndian)
        }
        keptCommands.append(Data(bytes: &macCatalystCommand,
                                 count: MemoryLayout<build_version_command>.size))

        let newSizeofcmds = keptCommands.count
        let overlap = newSizeofcmds - Int(header.sizeofcmds)
        if overlap > 0 {
            if oldCommandsEnd + overlap > binary.count {
                print("Cannot replace version commands: not enough space after load commands")
                throw PlayCoverError.appCorrupted
            }
            if let nonZero = binary[oldCommandsEnd ..< oldCommandsEnd + overlap]
                .first(where: { $0 != 0 }) {
                print("Non zero value \(nonZero) found after load commands. "
                    + "Injection may overlap data section")
            }
            binary.replaceSubrange(headerSize..<oldCommandsEnd,
                                   with: Data(keptCommands[0 ..< oldCommandsEnd - headerSize]))
            binary.replaceSubrange(oldCommandsEnd..<oldCommandsEnd + overlap,
                                   with: Data(keptCommands[(oldCommandsEnd - headerSize)..<newSizeofcmds]))
        } else {
            binary.replaceSubrange(headerSize..<oldCommandsEnd, with: keptCommands)
            if newSizeofcmds < oldCommandsEnd - headerSize {
                binary.replaceSubrange(headerSize + newSizeofcmds ..< oldCommandsEnd,
                                       with: Data(count: oldCommandsEnd - headerSize - newSizeofcmds))
            }
        }

        header.ncmds = header.ncmds - UInt32(removedCount) + 1
        header.sizeofcmds = UInt32(newSizeofcmds)
        if shouldSwap {
            swap_mach_header_64(&header, NX_BigEndian)
        }
        binary.replaceSubrange(0..<headerSize, with: Data(bytes: &header, count: headerSize))
    }

    private static func isVersionCommand(_ cmd: UInt32) -> Bool {
        [UInt32(LC_VERSION_MIN_IPHONEOS),
         UInt32(LC_VERSION_MIN_MACOSX),
         UInt32(LC_VERSION_MIN_TVOS),
         UInt32(LC_VERSION_MIN_WATCHOS),
         UInt32(LC_BUILD_VERSION)].contains(cmd)
    }

    private static func versionCommandName(_ cmd: UInt32) -> String {
        switch cmd {
        case UInt32(LC_VERSION_MIN_IPHONEOS): return "LC_VERSION_MIN_IPHONEOS"
        case UInt32(LC_VERSION_MIN_MACOSX): return "LC_VERSION_MIN_MACOSX"
        case UInt32(LC_VERSION_MIN_TVOS): return "LC_VERSION_MIN_TVOS"
        case UInt32(LC_VERSION_MIN_WATCHOS): return "LC_VERSION_MIN_WATCHOS"
        case UInt32(LC_BUILD_VERSION): return "LC_BUILD_VERSION"
        default: return "unknown(\(cmd))"
        }
    }

    static func replaceLastCommand(_ binary: inout Data,
                                   satisfy isTargetCommand: (Data, Bool) -> Bool,
                                   with getNewCommandData: (Bool) -> Data?,
                                   atEnd shouldAppend: Bool) throws {
        let headerSize = MemoryLayout<mach_header_64>.size
        var header = binary.extract(mach_header_64.self)
        var shouldSwap = false

        var oldCommandStart = headerSize
        var oldCommandSize: UInt32 = 0

        let movedCommandsEnd = try iterateLoadCommands(binary: binary) { offset, needSwap in
            let loadCommand = binary.extract(load_command.self,
                                             offset: offset,
                                             swap: needSwap ? swap_load_command:nil)
            if isTargetCommand(binary[offset ..< offset+Int(loadCommand.cmdsize)], needSwap) {
                oldCommandStart = offset
                oldCommandSize = loadCommand.cmdsize
                shouldSwap = needSwap
            }
            return false
        }
        if movedCommandsEnd != headerSize + Int(header.sizeofcmds) {
            print("Error while replacing load command: end of commands mismatch")
        }

        let oldCommandEnd = oldCommandStart + Int(oldCommandSize)
        guard let newCommandData = getNewCommandData(shouldSwap) else {
            return
        }
        let newCommandSize = UInt32(newCommandData.count)

        var resultingCommandsData = binary[oldCommandEnd..<movedCommandsEnd]
        if shouldAppend {
            resultingCommandsData.append(newCommandData)
        } else {
            resultingCommandsData.insert(contentsOf: newCommandData,
                                         at: resultingCommandsData.startIndex)
        }

        let injectionEnd = movedCommandsEnd - Int(oldCommandSize) + Int(newCommandSize)
        if injectionEnd > movedCommandsEnd {
            if let nonZero = binary[movedCommandsEnd ..< injectionEnd].first(where: {$0 != 0}) {
                print("Non zero value \(nonZero) found after load commands. Injection may overlap data section")
            }
        } else {
            binary.replaceSubrange(injectionEnd ..< movedCommandsEnd,
                                   with: Data(count: movedCommandsEnd - injectionEnd))
        }
        binary.replaceSubrange(oldCommandStart..<injectionEnd, with: resultingCommandsData)

        // Write new header data
        header.sizeofcmds -= oldCommandSize
        header.sizeofcmds += newCommandSize
        let newHeaderData = Data(bytes: &header, count: headerSize)
        binary.replaceSubrange(0..<headerSize, with: newHeaderData)
    }

    static func iterateLoadCommands(binary: Data, _ evaluate: (Int, Bool) -> Bool) throws -> Int {
        let headerSize = MemoryLayout<mach_header_64>.size
        var header = binary.extract(mach_header_64.self)
        var offset = headerSize
        let shouldSwap = header.magic == MH_CIGAM_64
        if  shouldSwap {
            swap_mach_header_64(&header, NXHostByteOrder())
            print("Slim Mach-O has reversed byte order")
        }

        let allCommandsEnd = headerSize + Int(header.sizeofcmds)
        if allCommandsEnd >= binary.count || allCommandsEnd <= headerSize {
            print("Cannot iterate load commands: Mach-O file is corrupted(-1)")
            throw PlayCoverError.appCorrupted
        }
        for index in 0..<header.ncmds {
            let loadCommand = binary.extract(load_command.self,
                                             offset: offset,
                                             swap: shouldSwap ? swap_load_command:nil)
            let commandEnd = offset + Int(loadCommand.cmdsize)
            if commandEnd > allCommandsEnd || commandEnd <= offset {
                print("Cannot iterate load commands: Mach-O file is corrupted(\(index))")
                throw PlayCoverError.appCorrupted
            }
            let terminated = evaluate(offset, shouldSwap)
            offset = commandEnd
            if terminated {
                break
            }
        }
        return offset
    }

    static func isMachoEncrypted(atURL url: URL) throws -> Bool {
        var binary = try Data(contentsOf: url)
        try stripBinary(&binary)
        var result = false
        _ = try iterateLoadCommands(binary: binary) { offset, shouldSwap in
            let loadCommand = binary.extract(load_command.self,
                                             offset: offset,
                                             swap: shouldSwap ? swap_load_command:nil)
            if loadCommand.cmd == UInt32(LC_ENCRYPTION_INFO_64) {
                let infoCommand = binary.extract(encryption_info_command_64.self,
                                                 offset: offset,
                                                 swap: shouldSwap ? swap_encryption_command_64:nil)
                result = infoCommand.cryptid != 0
                return true
            }
            return false
        }
        return result
    }

    static func isMachoValidArch(_ url: URL) throws -> Bool {
        var binary = try Data(contentsOf: url)
        try stripBinary(&binary)
        var result = false
        _ = try iterateLoadCommands(binary: binary) { offset, shouldSwap in
            let loadCommand = binary.extract(load_command.self,
                                             offset: offset,
                                             swap: shouldSwap ? swap_load_command:nil)
            if loadCommand.cmd == UInt32(LC_BUILD_VERSION) {
                let versionCommand = binary.extract(build_version_command.self,
                                                    offset: offset,
                                                    swap: shouldSwap ? swap_build_version_command:nil)
                result = versionCommand.platform == PLATFORM_MACCATALYST
                return true
            }
            return false
        }
        return result
    }

    static func containsNonCatalystVersionCommand(_ url: URL) throws -> Bool {
        var binary = try Data(contentsOf: url)
        try stripBinary(&binary)
        var result = false
        _ = try iterateLoadCommands(binary: binary) { offset, shouldSwap in
            let loadCommand = binary.extract(load_command.self,
                                             offset: offset,
                                             swap: shouldSwap ? swap_load_command:nil)
            if loadCommand.cmd == UInt32(LC_BUILD_VERSION) {
                let versionCommand = binary.extract(build_version_command.self,
                                                    offset: offset,
                                                    swap: shouldSwap ? swap_build_version_command:nil)
                result = versionCommand.platform != PLATFORM_MACCATALYST
            } else if isVersionCommand(loadCommand.cmd) {
                result = true
            }
            return result
        }
        return result
    }
}
