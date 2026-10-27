# loadertest

## Installation

```bash
npm install
```

## Usage

```javascript
const { createClient } = require('./src');
const client = createClient({ apiKey: process.env.API_KEY });
const result = await client.process('input');
console.log(result);
```

## Contributing

Pull requests are welcome. Ensure tests pass with `npm test` before submitting.
