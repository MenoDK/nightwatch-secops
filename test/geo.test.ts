import { describe, expect, it } from 'vitest';
import { DEMO_GEO, StaticGeo, haversineKm, travelVerdict } from '../src/lib/geo.js';

const lisbon = { lat: 38.72, lon: -9.14 };
const tokyo = { lat: 35.68, lon: 139.69 };
const porto = { lat: 41.15, lon: -8.61 };
const limits = { maxSpeedKmh: 900, minKm: 300 };
const MIN = 60_000;

describe('haversineKm', () => {
  it('is zero for the same point and symmetric', () => {
    expect(haversineKm(lisbon, lisbon)).toBe(0);
    expect(haversineKm(lisbon, tokyo)).toBeCloseTo(haversineKm(tokyo, lisbon), 6);
  });

  it('knows Lisbon is about 11,100 km from Tokyo', () => {
    expect(haversineKm(lisbon, tokyo)).toBeGreaterThan(11_000);
    expect(haversineKm(lisbon, tokyo)).toBeLessThan(11_300);
  });
});

describe('travelVerdict', () => {
  const last = (minutesAgo: number, at = lisbon, now = 1_000_000 * MIN) => ({
    last: { ...at, ts: now - minutesAgo * MIN },
    now,
  });

  it('flags Lisbon to Tokyo in ten minutes', () => {
    const { last: l, now } = last(10);
    const verdict = travelVerdict(l, tokyo, now, limits);
    expect(verdict.impossible).toBe(true);
    expect(verdict.speedKmh).toBeGreaterThan(60_000);
  });

  it('allows the same journey after a day', () => {
    const { last: l, now } = last(24 * 60);
    expect(travelVerdict(l, tokyo, now, limits).impossible).toBe(false);
  });

  it('has no cliff: 19 and 21 minutes for a 600 km hop are judged by speed, not by a box', () => {
    const farEnough = { lat: lisbon.lat + 5.4, lon: lisbon.lon }; // roughly 600 km north
    const a = last(19);
    const b = last(21);
    expect(travelVerdict(a.last, farEnough, a.now, limits).impossible).toBe(true);
    expect(travelVerdict(b.last, farEnough, b.now, limits).impossible).toBe(true);
    const c = last(45);
    expect(travelVerdict(c.last, farEnough, c.now, limits).impossible).toBe(false); // ~800 km/h is a jet
  });

  it('ignores a short hop however fast it was: that is geolocation noise', () => {
    const { last: l, now } = last(1, lisbon);
    expect(travelVerdict(l, porto, now, limits).impossible).toBe(false);
  });

  it('treats two requests in the same instant as very fast, not as a division by zero', () => {
    const l = { ...lisbon, ts: 5 * MIN };
    const verdict = travelVerdict(l, tokyo, 5 * MIN, limits);
    expect(verdict.impossible).toBe(true);
    expect(Number.isFinite(verdict.speedKmh)).toBe(true);
  });

  it('never goes negative when the clock moved backwards', () => {
    const l = { ...lisbon, ts: 10 * MIN };
    expect(travelVerdict(l, tokyo, 5 * MIN, limits).minutes).toBe(0);
  });
});

describe('StaticGeo', () => {
  it('finds a position by range and says nothing about an unknown address', async () => {
    expect(await DEMO_GEO.lookup('203.0.113.77')).toEqual(lisbon);
    expect(await DEMO_GEO.lookup('198.51.100.1')).toEqual(tokyo);
    expect(await DEMO_GEO.lookup('8.8.8.8')).toBeNull();
    expect(await new StaticGeo({ 'not a range': lisbon }).lookup('203.0.113.77')).toBeNull();
  });
});
