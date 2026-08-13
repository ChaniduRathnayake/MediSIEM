import { describe, test, expect } from 'vitest';
import { isLifeCriticalDevice } from '../AlertBadges';

describe('isLifeCriticalDevice', () => {
  test('true only for deviceCriticality === "critical", not "high"', () => {
    expect(isLifeCriticalDevice({ deviceCriticality: 'critical' })).toBe(true);
    expect(isLifeCriticalDevice({ deviceCriticality: 'high' })).toBe(false);
    expect(isLifeCriticalDevice({ deviceCriticality: 'medium' })).toBe(false);
    expect(isLifeCriticalDevice({ deviceCriticality: 'low' })).toBe(false);
  });

  test('false when deviceCriticality is absent (device never onboarded in inventory)', () => {
    expect(isLifeCriticalDevice({})).toBe(false);
  });
});
