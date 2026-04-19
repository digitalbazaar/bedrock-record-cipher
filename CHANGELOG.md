# bedrock-record-cipher ChangeLog

## 1.2.0 - 2026-04-dd

### Added
- Allow the current KEK to be lazily loaded (on demand) instead of
  requiring it to be present at the time that `setCurrentKek()` is
  called.

## 1.1.1 - 2026-04-13

### Fixed
- Set a hard maximum (1000) on lazy-loaded KEKs using an LRU-cache to
  prevent memory exhaustion. If an application requires more than 1000
  lazy-loaded KEKs to be concurrently in memory, it can implement that
  externally and use the `kekLoader()` option to call into this larger,
  persistent storage area.

## 1.1.0 - 2026-04-13

### Added
- Add optional `kekLoader` parameter to `RecordCipher` to allow lazy-loading
  of KEKs.

## 1.0.1 - 2026-04-11

### Fixed
- Fix `currentKekId` validation.

## 1.0.0 - 2026-04-06

- See git history for changes.
