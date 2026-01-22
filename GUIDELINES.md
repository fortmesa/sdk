# Developer Guidelines

## Adding New Parsers

1. Create parser in `test/{scanner}/`
2. Parse scanner output format (XML/JSON)
3. Map to SDK payload format
4. Test with sample data

## Payload Format

Assets must have:
- `deviceId` - unique identifier (min 8 chars)
- `assetLabel` - display name

Vulnerabilities must have:
- `deviceId` - matching asset ID
- `findingId` OR `title`

## Anti-Patterns

### ❌ Missing Validation
**Pattern**: Submitting without checking required fields.
**Fix**: SDK validates but check early.

### ❌ Large Uncompressed Payloads
**Pattern**: Sending >4KB without compression.
**Fix**: SDK auto-compresses, but batch appropriately.

## Release Process

1. Update version in package.json
2. Push to origin (Bitbucket)
3. Consider syncing to github remote
