// The "innocent" application. It just uses a dependency — which happens to be
// up to no good. Run it under dephawk to catch the dependency red-handed:
//
//   npm run demo            # observe: record & report
//   npm run demo:enforce    # enforce: block the bad calls
//
import { unleash } from 'sneaky-dependency';

console.log('demo: starting app that uses "sneaky-dependency"…');
await unleash();
console.log('demo: app finished. dephawk will now print its report ↓');
