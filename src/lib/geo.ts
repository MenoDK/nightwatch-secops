import { type Cidr, matchesAny, parseCidr } from './net.js';

export interface Position {
  lat: number;
  lon: number;
}

export interface LastSeen extends Position {
  /** Epoch milliseconds, from the injected clock. */
  ts: number;
}

export function haversineKm(a: Position, b: Position): number {
  const radius = 6371;
  const rad = (degrees: number) => (degrees * Math.PI) / 180;
  const dLat = rad(b.lat - a.lat);
  const dLon = rad(b.lon - a.lon);
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(rad(a.lat)) * Math.cos(rad(b.lat)) * Math.sin(dLon / 2) ** 2;
  return radius * 2 * Math.atan2(Math.sqrt(h), Math.sqrt(1 - h));
}

export interface TravelLimits {
  /** Faster than a passenger jet is not travel. */
  maxSpeedKmh: number;
  /** Below this distance a jump is geolocation noise (VPN exits, mobile carriers), whatever the speed. */
  minKm: number;
}

export interface TravelVerdict {
  impossible: boolean;
  km: number;
  minutes: number;
  speedKmh: number;
}

/**
 * Could one person have been at both places? The rule is a speed, not a "within N minutes and over N km" box: a box has
 * a cliff (19 minutes and 601 km alarms, 21 minutes does not) and a speed limit does not.
 */
export function travelVerdict(last: LastSeen, current: Position, nowMs: number, limits: TravelLimits): TravelVerdict {
  const km = haversineKm(last, current);
  const minutes = Math.max(0, (nowMs - last.ts) / 60_000);
  // Under a second apart is still "very fast", never a division by zero.
  const hours = Math.max(minutes, 1 / 60) / 60;
  const speedKmh = km / hours;
  return { impossible: km > limits.minKm && speedKmh > limits.maxSpeedKmh, km, minutes, speedKmh };
}

/** Where is this address? Injected, so the engine never calls a third-party geolocation service on its own. */
export interface GeoProvider {
  lookup(ip: string): Promise<Position | null>;
}

/** A fixed table of ranges: what the demo and the tests use. A deployment would put a database or a service behind the same interface. */
export class StaticGeo implements GeoProvider {
  readonly #entries: { cidr: Cidr; position: Position }[];

  constructor(table: Record<string, Position>) {
    this.#entries = Object.entries(table).flatMap(([range, position]) => {
      const cidr = parseCidr(range);
      return cidr ? [{ cidr, position }] : [];
    });
  }

  async lookup(ip: string): Promise<Position | null> {
    return this.#entries.find((entry) => matchesAny(ip, [entry.cidr]))?.position ?? null;
  }
}

/** Documentation ranges (RFC 5737) standing in for three far-apart cities: addresses that exist nowhere. */
export const DEMO_GEO = new StaticGeo({
  '203.0.113.0/24': { lat: 38.72, lon: -9.14 }, // Lisbon
  '198.51.100.0/24': { lat: 35.68, lon: 139.69 }, // Tokyo
  '192.0.2.0/24': { lat: -23.55, lon: -46.63 }, // São Paulo
});
