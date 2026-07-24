import { describe, it, expect } from 'vitest';
import {
  CAPABILITIES,
  CAPABILITY_META,
  isCapability,
} from '../../src/domain/capability.js';

describe('capability metadata', () => {
  it('has metadata for every capability', () => {
    for (const cap of CAPABILITIES) {
      expect(CAPABILITY_META[cap]).toBeDefined();
      expect(CAPABILITY_META[cap].label.length).toBeGreaterThan(0);
    }
  });

  it('recognises valid capabilities and rejects others', () => {
    expect(isCapability('fs.read')).toBe(true);
    expect(isCapability('net.connect')).toBe(true);
    expect(isCapability('quantum.teleport')).toBe(false);
  });
});
