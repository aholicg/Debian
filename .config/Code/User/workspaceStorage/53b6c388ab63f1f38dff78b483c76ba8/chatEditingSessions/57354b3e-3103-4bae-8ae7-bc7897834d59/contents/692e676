const fs = require('node:fs/promises')
const path = require('node:path')
const { load } = require('pe-library/cjs')

let peLibraryPromise = null

function getPeLibrary() {
  if (!peLibraryPromise) {
    peLibraryPromise = load()
  }
  return peLibraryPromise
}

async function readInitialBytes(filePath, byteCount) {
  const handle = await fs.open(filePath, 'r')
  try {
    const stats = await handle.stat()
    const length = Math.min(stats.size, byteCount)
    const buffer = Buffer.alloc(length)
    if (length === 0) {
      return buffer
    }
    await handle.read(buffer, 0, length, 0)
    return buffer
  } finally {
    await handle.close()
  }
}

function checkPeSignatures(buffer) {
  // Check for DOS header signature "MZ" at offset 0
  if (buffer.length < 64) {
    return false
  }
  
  if (buffer[0] !== 0x4D || buffer[1] !== 0x5A) { // 'MZ'
    return false
  }
  
  // Get PE header offset from DOS header (at offset 0x3C)
  const peOffset = buffer.readUInt32LE(0x3C)
  
  // Check if we have enough data to read PE signature
  if (buffer.length < peOffset + 4) {
    // Need more data to verify PE signature
    return null // Inconclusive
  }
  
  // Check for PE signature "PE\0\0" at the PE offset
  if (buffer[peOffset] === 0x50 && buffer[peOffset + 1] === 0x45 &&
      buffer[peOffset + 2] === 0x00 && buffer[peOffset + 3] === 0x00) {
    return true
  }
  
  return false
}

async function determinePeStatus(filePath) {
  const absolutePath = path.resolve(filePath)
  const peLib = await getPeLibrary()

  try {
    // Read larger initial buffer to handle PE files with large headers
    const headerBuffer = await readInitialBytes(absolutePath, 64 * 1024) // 64KB
    
    // First, do quick signature check
    const signatureCheck = checkPeSignatures(headerBuffer)
    
    if (signatureCheck === false) {
      // Definitely not a PE file
      return { isPe: false }
    }
    
    // If signature check passed or inconclusive, try parsing with pe-library
    try {
      peLib.NtExecutable.from(headerBuffer)
      return { isPe: true }
    } catch (headerErr) {
      // If initial buffer failed, check file size before reading full file
      const stats = await fs.stat(absolutePath)
      
      // For very large files (>100MB), avoid reading entire file
      if (stats.size > 100 * 1024 * 1024) {
        // For large files, rely on signature check
        if (signatureCheck === true) {
          return { isPe: true }
        }
        return { isPe: false, error: 'File too large for full PE validation' }
      }
      
      // For smaller files, try reading the full file
      try {
        const fullBuffer = await fs.readFile(absolutePath)
        peLib.NtExecutable.from(fullBuffer)
        return { isPe: true }
      } catch (fullErr) {
        // If signature check passed but parsing failed, still consider it PE
        if (signatureCheck === true) {
          return { isPe: true }
        }
        return { isPe: false }
      }
    }
  } catch (err) {
    return { isPe: false, error: err instanceof Error ? err.message : String(err) }
  }
}

module.exports = {
  determinePeStatus,
}
